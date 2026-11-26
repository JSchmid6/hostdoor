import { createHash, randomBytes } from "node:crypto";

import type { JobRecord } from "@wireguard-ops-cockpit/domain";

import type { TelegramApprovalSettings } from "./config.js";
import type { CockpitDatabase, TelegramOffer } from "./db.js";
import { hashCanonical, type ExecutionEnvelope } from "./hermes-security.js";
import type { HostRunManifest, InstanceRole } from "./host-run.js";

// Jochens Ja per Telegram für Klasse A (card t_1e9bc441, doc/setup/telegram-freigabe.md).
//
// A host run on box that stopped for the operator may be approved with one tap
// in the Cockpit's OWN Telegram chat instead of a click in the Cockpit, when it
// belongs to the narrow class A (a throwaway guest or a port only inside the
// workshop network vmbr1). What guards it:
//
//   source      the Cockpit sends the offer itself with its own bot and reads
//               the tap itself (getUpdates). The bot token lives in
//               telegram.env (root-owned, the agents never see it). Telegram
//               authenticates who tapped; no agent text, no gateway signature,
//               no "ja" recognized in a message (messages are not even read).
//   class       the doorkeeper's CLASS_A line plus structural facts of the job
//               (classAEligibility): box, host door, nothing but X3 findings,
//               risk only contained/exposure, no package, no reviewed files,
//               no breaker, no update review, no safety stop.
//   binding     the offer carries a single-use random nonce (stored as hash),
//               the message id and the hash of the message text Telegram
//               returned, and a binding over the envelope's reviewed content
//               (job, intent, plan, review, policy, manifest, capabilities).
//               Any drift, another sender or chat, another message, an edited
//               message, a second tap or a tap after the window: no approval.
//   window      30 minutes from the offer, never beyond the envelope's own
//               deadline; no re-signing after expiry on this way.
//   fail closed anything missing → nothing happens; the Cockpit click stays.

export const TELEGRAM_WINDOW_MINUTES = 30;
// Findings the doorkeeper may raise on a class-A run (exposure inside vmbr1).
const CLASS_A_FINDINGS = new Set(["X3"]);
const CLASS_A_RISKS = new Set(["contained", "exposure"]);
const BUTTON_DATA = /^ja:([A-Za-z0-9_-]{24})$/;
// After a failed send the next attempt for that job waits this long.
const OFFER_RETRY_MS = 5 * 60_000;

export type TelegramCall = (method: string, body: Record<string, unknown>) => Promise<unknown>;

// The Bot API over HTTPS. Errors never carry the URL: it holds the token.
export function telegramBotCall(token: string, fetchImpl: typeof fetch = fetch): TelegramCall {
  return async (method, body) => {
    let response: Response;
    try {
      response = await fetchImpl(`https://api.telegram.org/bot${token}/${method}`, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body), signal: AbortSignal.timeout(20_000),
      });
    } catch {
      throw new Error(`telegram ${method}: network error`);
    }
    const data = await response.json().catch(() => null) as { ok?: unknown; result?: unknown; description?: unknown } | null;
    if (!response.ok || data?.ok !== true) {
      const description = typeof data?.description === "string" ? ` ${data.description.split(token).join("<token>").slice(0, 200)}` : "";
      throw new Error(`telegram ${method}: HTTP ${response.status}${description}`);
    }
    return data.result;
  };
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

export interface ClassAEligibility {
  eligible: boolean;
  reasons: string[];
  why: string;
}

// Whether this job may be offered for (and approved by) a tap in Telegram.
// Every condition is a stored, structured fact of the job; the only judgment is
// the doorkeeper's CLASS_A line. Any missing fact is a reason against.
export function classAEligibility(job: JobRecord | null, role: InstanceRole | null | undefined, now = Date.now()): ClassAEligibility {
  const reasons: string[] = [];
  const no = (reason: string) => { reasons.push(reason); };
  if (role !== "box") no("instance role is not box");
  if (!job) return { eligible: false, reasons: [...reasons, "job not found"], why: "" };
  if (job.subjectId !== "hermes-change") no("not a change job");
  if (job.status !== "blocked_user_approval") no(`status ${job.status}, not blocked_user_approval`);
  const output = record(job.output);
  const hostRun = output.hostRun as HostRunManifest | null | undefined;
  if (!hostRun || typeof hostRun !== "object") no("not a run of the host door");
  if (output.manifest) no("carries a capability manifest");
  if (output.breaker) no("held by the circuit breaker");
  if (output.updateReview) no("carries an update review");
  if (JSON.stringify(output.capabilities) !== JSON.stringify(["host.run"])) no("capabilities are not exactly host.run");
  if (hostRun && typeof hostRun === "object") {
    const risks = Array.isArray(hostRun.risk) ? hostRun.risk : [];
    const foreign = risks.filter((risk) => !CLASS_A_RISKS.has(risk));
    if (foreign.length) no(`declared risk ${foreign.join(", ")}`);
    if (hostRun.package) no("carries a package");
  }
  const envelope = output.envelope as ExecutionEnvelope | undefined;
  if (!envelope || typeof envelope !== "object") no("no execution envelope");
  else {
    if (envelope.operatorApproved) no("already approved");
    if (!(Date.parse(envelope.expiresAt) > now)) no("execution envelope expired");
  }
  const policy = record(output.policy);
  if (policy.status !== "blocked_user_approval") no("policy did not ask the operator");
  const details = record(record(output.safety).details);
  if (details.schemaVersion !== "host-run-review/v1") no("no doorkeeper review");
  if (details.complete !== true) no("doorkeeper material incomplete");
  if (details.safetyStops !== 0) no("doorkeeper stopped by the safety classifier");
  if (details.reviewerError) no("doorkeeper error");
  if (details.verdict !== "pass" && details.verdict !== "flag") no(`doorkeeper verdict ${String(details.verdict)}`);
  if (!Array.isArray(details.reviewedFiles) || details.reviewedFiles.length > 0) no("runs code from a reviewed repository");
  const findings = Array.isArray(details.findings) ? details.findings.map(record) : null;
  if (!findings) no("findings unreadable");
  else {
    // Every finding counts, also one discarded for missing evidence.
    const foreign = findings.filter((finding) => !CLASS_A_FINDINGS.has(String(finding.class)));
    if (foreign.length) no(`finding outside class A: ${foreign.map((finding) => String(finding.class || "?")).join(", ")}`);
  }
  const classA = record(details.classA);
  if (classA.value !== "yes") no("the doorkeeper did not judge it class A");
  return { eligible: reasons.length === 0, reasons, why: typeof classA.why === "string" ? classA.why : "" };
}

// The reviewed content the tap approves: the envelope without its signature
// and deadlines (a re-signed envelope with other content never matches).
export function offerBinding(job: JobRecord): string | null {
  const envelope = record(job.output).envelope as ExecutionEnvelope | undefined;
  if (!envelope || typeof envelope !== "object") return null;
  return hashCanonical({
    jobId: envelope.jobId, actorId: envelope.actorId, sessionId: envelope.sessionId, intentHash: envelope.intentHash,
    evidence: envelope.evidence, planHash: envelope.planHash, safetyHash: envelope.safetyHash, policyHash: envelope.policyHash,
    capabilities: envelope.capabilities, manifestHash: envelope.manifestHash ?? null,
  });
}

function clipText(value: unknown, limit: number): string {
  const text = typeof value === "string" ? value.replace(/\s+/g, " ").trim() : "";
  return text.length > limit ? `${text.slice(0, limit)} …` : text;
}

function berlin(iso: string): string {
  return new Date(iso).toLocaleString("de-DE", { timeZone: "Europe/Berlin", day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
}

// The offer as the Cockpit writes it: from the job's own record, plain text
// (no parse mode), never text the requester could format.
export function offerText(job: JobRecord, eligibility: ClassAEligibility, expiresAt: string, link: string): string {
  const output = record(job.output);
  const hostRun = record(output.hostRun);
  const request = record(output.request);
  const explanation = record(output.explanation);
  const steps = Array.isArray(hostRun.steps) ? hostRun.steps.length : 0;
  return [
    "Cockpit box: Freigabe Klasse A",
    `Job: ${job.id}`,
    `Vorgang: ${clipText(request.operation, 80) || "–"}`,
    `Absicht: ${clipText(explanation.intent ?? request.intent, 500)}`,
    `Plan: ${clipText(hostRun.name, 120)} — ${clipText(hostRun.purpose, 400)} (${steps} Schritte, Risiko ${Array.isArray(hostRun.risk) ? hostRun.risk.join(", ") : "?"})`,
    `Türsteher: ${clipText(record(output.policy).reason, 600)}`,
    `Klasse A: ${clipText(eligibility.why, 300) || "ja"}`,
    `Prüfsumme: ${(offerBinding(job) ?? "").slice(0, 12)}`,
    `Gültig bis: ${berlin(expiresAt)}`,
    "",
    "„Freigeben“ gibt genau diesen geprüften Plan frei, einmal. Ablehnen oder genauer ansehen im Cockpit:",
    link,
  ].join("\n").slice(0, 3900);
}

export interface TelegramApprovalDeps {
  settings: TelegramApprovalSettings;
  role: InstanceRole | null | undefined;
  database: CockpitDatabase;
  call: TelegramCall;
  // The same decision as the Cockpit's approval route (app.ts decideChange).
  approve: (job: JobRecord, reason: string, via: Record<string, unknown>) => Promise<{ ok: boolean; message: string }>;
  // Signature, binding and drift of the stored envelope against the job (expiry included).
  envelopeErrors: (job: JobRecord) => string[];
  link: (jobId: string) => string;
  now?: () => number;
  log?: (line: string) => void;
}

interface CallbackQuery {
  id?: unknown;
  from?: { id?: unknown; is_bot?: unknown };
  data?: unknown;
  message?: { message_id?: unknown; chat?: { id?: unknown }; text?: unknown; edit_date?: unknown };
}

export function createTelegramApproval(deps: TelegramApprovalDeps) {
  const now = deps.now ?? (() => Date.now());
  const log = deps.log ?? ((line: string) => console.log(line));
  const retryAfter = new Map<string, number>();
  let offset = 0;
  let busy = false;

  function audit(action: string, jobId: string | null, details: Record<string, unknown>): void {
    deps.database.createAudit({ actorId: null, action, targetType: "job", targetId: jobId, details });
  }

  async function offerPending(): Promise<void> {
    for (const job of deps.database.listJobsByStatus("hermes-change", "blocked_user_approval")) {
      if (deps.database.getTelegramOfferForJob(job.id)) continue;
      if ((retryAfter.get(job.id) ?? 0) > now()) continue;
      const eligibility = classAEligibility(job, deps.role, now());
      if (!eligibility.eligible) continue;
      if (deps.envelopeErrors(job).length > 0) continue;
      const binding = offerBinding(job);
      const envelope = record(job.output).envelope as ExecutionEnvelope;
      if (!binding) continue;
      const expiresAt = new Date(Math.min(now() + TELEGRAM_WINDOW_MINUTES * 60_000, Date.parse(envelope.expiresAt))).toISOString();
      const nonce = randomBytes(18).toString("base64url");
      try {
        const sent = record(await deps.call("sendMessage", {
          chat_id: deps.settings.operatorId,
          text: offerText(job, eligibility, expiresAt, deps.link(job.id)),
          link_preview_options: { is_disabled: true },
          reply_markup: { inline_keyboard: [[{ text: "✅ Freigeben", callback_data: `ja:${nonce}` }]] },
        }));
        const messageId = sent.message_id;
        const chatId = String(record(sent.chat).id ?? "");
        if (!Number.isSafeInteger(messageId) || chatId !== deps.settings.operatorId || typeof sent.text !== "string") throw new Error("telegram sendMessage: unexpected answer");
        deps.database.createTelegramOffer({ jobId: job.id, nonceHash: sha256(nonce), binding, chatId, messageId: messageId as number, textHash: sha256(sent.text), expiresAt });
        audit("hermes.change.telegram_offered", job.id, { messageId, chatId, expiresAt, binding: binding.slice(0, 16), classA: eligibility.why.slice(0, 300) });
      } catch (error) {
        retryAfter.set(job.id, now() + OFFER_RETRY_MS);
        log(`telegram-approval: offer for job ${job.id} not sent: ${error instanceof Error ? error.message : "error"}`);
      }
    }
  }

  async function refuse(callback: CallbackQuery, reason: string, offer: TelegramOffer | null): Promise<{ approved: false; reason: string }> {
    audit("hermes.change.telegram_refused", offer?.jobId ?? null, {
      reason, fromId: String(callback.from?.id ?? ""), messageId: callback.message?.message_id ?? null, offerId: offer?.id ?? null,
    });
    await answer(callback, `Nicht freigegeben: ${reason}. Im Cockpit entscheiden.`);
    return { approved: false, reason };
  }

  async function answer(callback: CallbackQuery, text: string): Promise<void> {
    if (typeof callback.id !== "string") return;
    try { await deps.call("answerCallbackQuery", { callback_query_id: callback.id, text: text.slice(0, 190), show_alert: true }); } catch { /* the decision stands */ }
  }

  // One tap. Every check is against what the Cockpit itself stored when it sent
  // the offer, and against the job as it is now.
  async function handleCallback(callback: CallbackQuery): Promise<{ approved: boolean; reason: string }> {
    const match = typeof callback.data === "string" ? callback.data.match(BUTTON_DATA) : null;
    if (!match) return refuse(callback, "unknown button", null);
    const offer = deps.database.getTelegramOfferByNonceHash(sha256(match[1]));
    if (!offer) return refuse(callback, "unknown offer", null);
    if (String(callback.from?.id ?? "") !== deps.settings.operatorId || callback.from?.is_bot === true) return refuse(callback, "other sender", offer);
    const message = callback.message;
    if (String(message?.chat?.id ?? "") !== offer.chatId || message?.message_id !== offer.messageId) return refuse(callback, "not the offer message", offer);
    if (message.edit_date !== undefined || typeof message.text !== "string" || sha256(message.text) !== offer.textHash) return refuse(callback, "offer message changed", offer);
    if (offer.usedAt) return refuse(callback, "already used", offer);
    if (now() > Date.parse(offer.expiresAt)) return refuse(callback, "window expired", offer);
    const job = deps.database.getJob(offer.jobId);
    const eligibility = classAEligibility(job, deps.role, now());
    if (!job || !eligibility.eligible) return refuse(callback, `no longer class A (${eligibility.reasons.join("; ").slice(0, 200)})`, offer);
    const envelopeErrors = deps.envelopeErrors(job);
    if (envelopeErrors.length) return refuse(callback, `envelope: ${envelopeErrors.join("; ")}`, offer);
    if (offerBinding(job) !== offer.binding) return refuse(callback, "job changed since the offer", offer);
    if (!deps.database.useTelegramOffer(offer.id)) return refuse(callback, "already used", offer);
    const via = { channel: "telegram", fromId: deps.settings.operatorId, messageId: offer.messageId, offerId: offer.id, class: "A" };
    const result = await deps.approve(job, `Telegram-Ja Klasse A (Nachricht ${offer.messageId})`, via);
    if (!result.ok) {
      audit("hermes.change.telegram_failed", job.id, { offerId: offer.id, messageId: offer.messageId, message: result.message.slice(0, 300) });
      await answer(callback, `Nicht gestartet: ${result.message}`);
      return { approved: false, reason: result.message };
    }
    await answer(callback, "Freigegeben, der Lauf startet.");
    try {
      await deps.call("editMessageText", { chat_id: offer.chatId, message_id: offer.messageId, text: `${message.text}\n\n✅ Freigegeben ${berlin(new Date(now()).toISOString())}`, link_preview_options: { is_disabled: true } });
    } catch { /* the approval stands */ }
    return { approved: true, reason: "approved" };
  }

  async function pollUpdates(): Promise<void> {
    const updates = await deps.call("getUpdates", { offset, timeout: 0, allowed_updates: ["callback_query"] });
    for (const update of Array.isArray(updates) ? updates.map(record) : []) {
      if (Number.isSafeInteger(update.update_id)) offset = Math.max(offset, (update.update_id as number) + 1);
      if (update.callback_query) await handleCallback(update.callback_query as CallbackQuery);
    }
  }

  async function tick(): Promise<void> {
    if (busy) return;
    busy = true;
    try {
      await offerPending();
      await pollUpdates();
    } catch (error) {
      log(`telegram-approval: ${error instanceof Error ? error.message : "error"}`);
    } finally {
      busy = false;
    }
  }

  return { tick, offerPending, handleCallback };
}
