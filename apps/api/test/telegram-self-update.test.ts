import { createHmac } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import type { JobRecord } from "@wireguard-ops-cockpit/domain";

import { createApp } from "../src/app.js";
import type { AppConfig } from "../src/config.js";
import { CockpitDatabase } from "../src/db.js";
import { createExecutionEnvelope } from "../src/hermes-security.js";
import { eligibilityFor, selfUpdateEligibility, TELEGRAM_WINDOW_MINUTES } from "../src/telegram-approval.js";
import {
  parseUpdateReviewAnswer,
  SECOND_REVIEW_REPOSITORY_ID,
  SECOND_REVIEW_REPOSITORY_PATH,
  summarizeUpdateReview,
  updateReviewEvidence,
  verifySecondReview,
  type GithubFetch,
  type UpdateDiff,
  type UpdateReviewAnswer,
  type UpdateReviewOutcome,
} from "../src/update-review.js";

// Klasse A für Selbstupdates auf VPS und Lab0 (card t_efc1d03e): a self-update
// whose every installed commit the Cockpit itself proved on GitHub to be the
// merge of a PR with an Opus second review for exactly that head, and whose
// pre-install review stopped only on evidenced findings quoted from the
// reviewed diff, may be approved by Jochen's tap in the Cockpit's own chat.
// Backups (G10), secrets (G6), an INJECTION, a gap, the box host and every
// other stop stay with the Cockpit click.

const BROKER_SECRET = "executor-broker-test-secret";
const ENVELOPE_SECRET = "test-envelope-secret";
const OPERATOR = "8156515098";
const TOKEN = "123456789:AAH-test-token-for-the-cockpit-bot_0123";
const SHA = "0123456789abcdef0123456789abcdef01234567";
const BASE = "89abcdef0123456789abcdef0123456789abcdef";
const HEAD = "fedcba9876543210fedcba9876543210fedcba98";
const TREE = "1".repeat(40);
const HASH = "a".repeat(64);
const REPO = SECOND_REVIEW_REPOSITORY_PATH;
const OURS = { id: SECOND_REVIEW_REPOSITORY_ID, full_name: "JSchmid6/hostdoor" };
const MARKER = `Cockpit-Zweitpruefung: FREIGABE ${HEAD} opus`;
const QUOTED = "if (via.channel === \"telegram\") return approveAsOperator(job);";
const cleanup: Array<() => void | Promise<void>> = [];

afterEach(async () => {
  for (const step of cleanup.splice(0).reverse()) await step();
});

// The GitHub API as it answers for SHA = merge of PR #128 (head HEAD) onto BASE.
function pages(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    [`${REPO}/commits/${SHA}`]: { sha: SHA, parents: [{ sha: BASE }, { sha: HEAD }], commit: { tree: { sha: TREE } } },
    [`${REPO}/commits/${SHA}/pulls`]: [{ number: 128, merged_at: "2026-11-26T14:05:18Z", merge_commit_sha: SHA, head: { sha: HEAD }, base: { ref: "main", repo: OURS } }],
    [`${REPO}/compare/${BASE}...${HEAD}`]: { status: "ahead", behind_by: 0, ahead_by: 3 },
    [`${REPO}/commits/${HEAD}`]: { sha: HEAD, parents: [{ sha: BASE }], commit: { tree: { sha: TREE } } },
    [`${REPO}/issues/128/comments?per_page=100`]: [{ body: `Zweitpruefung FREIGABE\n\n${MARKER}\n`, author_association: "OWNER", user: { login: "JSchmid6" }, html_url: "https://github.com/JSchmid6/hostdoor/pull/128#c1" }],
    [`${REPO}/pulls/128/reviews?per_page=100`]: [],
    ...overrides,
  };
}

function github(overrides: Record<string, unknown> = {}): GithubFetch {
  const known = pages(overrides);
  return async (apiPath) => {
    if (!(apiPath in known) || known[apiPath] === undefined) throw new Error(`GET ${apiPath} answered 404`);
    return known[apiPath];
  };
}

function diff(): UpdateDiff {
  const file = "apps/api/src/app.ts";
  return {
    base: BASE, sha: SHA, diffSha256: HASH, baseSource: "state", commitSubject: "feat: Telegram-Ja",
    files: [{ status: "M", path: file, added: 1, deleted: 0, class: "focus-hunks" }],
    filesTotal: 1, stat: " 1 file changed, 1 insertion(+)\n",
    focusAreas: [{ kind: "approval", guarantees: ["G1"], reason: "approval route", files: [file], hunks: [], lockfiles: [], packages: [] }],
    excerpt: [{ path: file, text: [`diff --git a/${file} b/${file}`, `--- a/${file}`, `+++ b/${file}`, "@@ -10,2 +10,3 @@", "   const job = load();", `+  ${QUOTED}`, "   return job;", ""].join("\n") }],
    truncated: false, partialFiles: [], omittedFiles: [],
  };
}

// The reviewer's answer: one finding per [guarantee, severity, quote].
function answer(findings: Array<[string, string, string]>): string {
  return ["VERDICT: flag", ...findings.flatMap(([guarantee, severity, code], index) => [
    `FINDING: point ${index + 1}`, `GUARANTEE: ${guarantee}`, "FILE: apps/api/src/app.ts:10-12", `CODE: ${code}`, "REASON: approves without the browser session", `SEVERITY: ${severity}`,
  ])].join("\n");
}
const G1_HIGH = answer([["G1", "high", QUOTED]]);

describe("self-update class A: eligibility from the stored job", () => {
  const plan = ["```bash", `/usr/local/sbin/cockpit-self-update-action ${SHA}`, "```", "## Risk Zone", "yellow"].join("\n");
  async function job(options: {
    answer?: string; quoteFound?: boolean; github?: GithubFetch; patch?: Record<string, unknown>; review?: Record<string, unknown>;
    outcome?: Partial<UpdateReviewOutcome>; evidence?: "bound" | "other" | "none"; status?: JobRecord["status"];
  } = {}): Promise<JobRecord> {
    const parsed = parseUpdateReviewAnswer(options.answer ?? G1_HIGH);
    const reviewed: UpdateReviewAnswer = { ...parsed, findings: parsed.findings.map((finding) => ({ ...finding, quoteFound: options.quoteFound ?? true })) };
    const binding = { base: BASE, sha: SHA, diffSha256: HASH };
    const outcome: UpdateReviewOutcome = { kind: "self", bindings: [binding], coverage: [{ sha: SHA, incomplete: [], cut: [], omitted: [] }], answer: reviewed, ...options.outcome };
    outcome.secondReview ??= [await verifySecondReview(binding, options.github ?? github())];
    const evidence = options.evidence === "none" ? [] : updateReviewEvidence([options.evidence === "other" ? { ...binding, diffSha256: "b".repeat(64) } : binding]);
    const policy = { status: "blocked_user_approval" };
    const envelope = createExecutionEnvelope({
      jobId: "j1", actorId: "owner", sessionId: "s1", intent: "Selbstupdate", evidence, plan, safety: {}, policy,
      capabilities: ["self.update"], ttlMinutes: 30, signingSecret: ENVELOPE_SECRET,
    });
    return {
      id: "j1", sessionId: "s1", kind: "runbook", subjectId: "hermes-change", status: options.status ?? "blocked_user_approval", requiresApproval: false, approvalId: null,
      output: {
        plan, capabilities: ["self.update"], policy, envelope, safety: { verdict: "passed", details: {} },
        updateReview: { ...summarizeUpdateReview([diff()], outcome, null), planAllowed: true, ...options.review },
        ...options.patch,
      },
      createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), completedAt: null,
    } as unknown as JobRecord;
  }
  const reasons = (value: ReturnType<typeof selfUpdateEligibility>) => value.reasons.join("; ");

  it("offers a stopped self-update with a verified Opus second review on VPS and Lab0, never on box", async () => {
    const stopped = await job();
    expect(selfUpdateEligibility(stopped, "vps")).toMatchObject({ eligible: true, reasons: [], scope: "self-update" });
    expect(selfUpdateEligibility(stopped, "vps").why).toContain("#128, Head fedcba987654");
    expect(eligibilityFor(stopped, "lab0").eligible).toBe(true);
    // The box host stays with the click; there only the workshop class counts.
    expect(eligibilityFor(stopped, "box")).toMatchObject({ eligible: false, scope: "werkstatt" });
    expect(selfUpdateEligibility(stopped, "box").eligible).toBe(false);
    expect(selfUpdateEligibility(stopped, null).eligible).toBe(false);
    expect(selfUpdateEligibility(null, "vps").eligible).toBe(false);
  });

  it("needs the Cockpit's own proof of the marker for exactly this head, in this repository, by Opus", async () => {
    const pulls = `${REPO}/commits/${SHA}/pulls`;
    const pr = (pages()[pulls] as Array<Record<string, unknown>>)[0];
    const comments = `${REPO}/issues/128/comments?per_page=100`;
    const comment = (pages()[comments] as Array<Record<string, unknown>>)[0];
    const cases: Array<[string, Record<string, unknown>]> = [
      ["wrong head: the marker names another head", { [comments]: [{ ...comment, body: `Cockpit-Zweitpruefung: FREIGABE ${BASE} opus` }] }],
      ["wrong head: the PR head is not the merged parent", { [pulls]: [{ ...pr, head: { sha: BASE } }] }],
      ["missing marker", { [comments]: [{ ...comment, body: "FREIGABE" }] }],
      ["no comment at all", { [comments]: [] }],
      ["foreign marker: an outsider wrote it", { [comments]: [{ ...comment, author_association: "CONTRIBUTOR" }] }],
      ["foreign marker: quoted inside a line", { [comments]: [{ ...comment, body: `zitiert: ${MARKER}` }] }],
      ["marker of another model (sonnet)", { [comments]: [{ ...comment, body: `Cockpit-Zweitpruefung: FREIGABE ${HEAD} sonnet` }] }],
      ["marker of another model (codex)", { [comments]: [{ ...comment, body: `Cockpit-Zweitpruefung: FREIGABE ${HEAD} codex` }] }],
      ["other repository under the same name", { [pulls]: [{ ...pr, base: { ref: "main", repo: { id: 4711, full_name: "JSchmid6/hostdoor" } } }] }],
      ["fork base", { [pulls]: [{ ...pr, base: { ref: "main", repo: { id: 1, full_name: "evil/hostdoor" } } }] }],
      ["not merged", { [pulls]: [{ ...pr, merged_at: null }] }],
      ["merge changes the tree", { [`${REPO}/commits/${HEAD}`]: { commit: { tree: { sha: "2".repeat(40) } } } }],
      ["GitHub down", { [comments]: undefined }],
    ];
    for (const [name, overrides] of cases) {
      const value = selfUpdateEligibility(await job({ github: github(overrides) }), "vps");
      expect(value.eligible, name).toBe(false);
      expect(reasons(value), name).toContain("no verified second review");
    }
    // Every installed commit needs its own proof.
    const two = await job({ outcome: { bindings: [{ base: BASE, sha: SHA, diffSha256: HASH }, { base: SHA, sha: HEAD, diffSha256: HASH }] } });
    expect(selfUpdateEligibility(two, "vps").eligible).toBe(false);
  });

  it("offers nothing outside the scope: backups, secrets, injection, a gap, an unquoted finding", async () => {
    const cases: Array<[string, Parameters<typeof job>[0], string]> = [
      ["G10 backups", { answer: answer([["G1", "high", QUOTED], ["G10", "medium", QUOTED]]) }, "stays with the click"],
      ["G10 alone", { answer: answer([["G10", "high", QUOTED]]) }, "stays with the click"],
      ["G6 secrets", { answer: answer([["G1", "high", QUOTED], ["G6", "high", QUOTED]]) }, "stays with the click"],
      ["G1 that also names G10", { answer: answer([["G1 (also G10)", "high", QUOTED]]) }, "stays with the click"],
      ["INJECTION", { answer: answer([["G1", "high", QUOTED], ["INJECTION", "high", QUOTED]]) }, "injection"],
      ["UNVERIFIABLE beside the finding", { answer: answer([["G1", "high", QUOTED], ["UNVERIFIABLE", "high", QUOTED]]) }, "unverifiable point"],
      ["finding without a guarantee", { answer: answer([["G1", "high", QUOTED], ["approval", "high", QUOTED]]) }, "names no guarantee"],
      ["quote not in the reviewed diff", { quoteFound: false }, "quoted code not found"],
      ["only light findings (reported anyway)", { answer: answer([["G1", "medium", QUOTED]]) }, "no finding that the second review leaves"],
      ["incomplete coverage", { outcome: { coverage: [{ sha: SHA, incomplete: ["apps/api/src/app.ts"], cut: [], omitted: [] }] } }, "pre-install review incomplete"],
      ["reviewer error beside the finding", { outcome: { reviewerError: "pass 2 timed out" } }, "pre-install review incomplete"],
      ["plan stopped before the review", { review: { planAllowed: false } }, "stopped before the pre-install review"],
      ["plan flag missing (older job)", { review: { planAllowed: undefined } }, "stopped before the pre-install review"],
      ["reported review", { review: { reported: true } }, "reported"],
      ["dienste review", { review: { kind: "dienste" } }, "not a self-update review"],
      ["incomplete result", { review: { result: "incomplete" } }, "pre-install review incomplete"],
      ["host run", { patch: { hostRun: { steps: [] } } }, "host door"],
      ["capability manifest", { patch: { manifest: {} } }, "capability manifest"],
      ["breaker", { patch: { breaker: { closesAt: "x" } } }, "circuit breaker"],
      ["more than self.update", { patch: { capabilities: ["self.update", "read.host"] } }, "not exactly self.update"],
      ["safety review not passed", { patch: { safety: { verdict: "approval_required", details: {} } } }, "plan safety review"],
      ["safety classifier stop", { patch: { safety: { verdict: "passed", details: { safetyStops: 1 } } } }, "safety classifier"],
      ["policy other than the operator", { patch: { policy: { status: "blocked_prerequisite" } } }, "policy did not ask"],
      ["diff not bound to the envelope", { evidence: "other" }, "not bound to the execution envelope"],
      ["no review evidence in the envelope", { evidence: "none" }, "not bound to the execution envelope"],
      ["running job", { status: "running" }, "status running"],
    ];
    for (const [name, options, reason] of cases) {
      const value = selfUpdateEligibility(await job(options), "vps");
      expect(value.eligible, name).toBe(false);
      expect(reasons(value), name).toContain(reason);
    }
    const stopped = await job();
    const output = stopped.output as Record<string, any>;
    const expired = { ...stopped, output: { ...output, envelope: { ...output.envelope, expiresAt: new Date(Date.now() - 1).toISOString() } } } as JobRecord;
    expect(reasons(selfUpdateEligibility(expired, "vps"))).toContain("execution envelope expired");
    const approved = { ...stopped, output: { ...output, envelope: { ...output.envelope, operatorApproved: true } } } as JobRecord;
    expect(reasons(selfUpdateEligibility(approved, "vps"))).toContain("already approved");
  });
});

// The whole way through the Cockpit: planner, diff, pre-install review, the
// second review on a stubbed GitHub, the stop, the offer, the tap, the install.

function listen(socketPath: string, answerFor: (request: Record<string, any>) => Record<string, unknown>): Promise<Array<Record<string, any>>> {
  const seen: Array<Record<string, any>> = [];
  const server = net.createServer((connection) => {
    let input = "";
    connection.setEncoding("utf8");
    connection.on("data", (chunk) => {
      input += chunk;
      if (!input.includes("\n")) return;
      const request = JSON.parse(input.slice(0, input.indexOf("\n")));
      seen.push(request);
      connection.end(JSON.stringify(answerFor(request)));
    });
  });
  cleanup.push(() => new Promise<void>((resolve) => server.close(() => resolve())));
  return new Promise((resolve) => server.listen(socketPath, () => resolve(seen)));
}

function config(dir: string, overrides: Partial<AppConfig>): AppConfig {
  return {
    apiHost: "127.0.0.1", apiPort: 3001, dbPath: path.join(dir, "cockpit.sqlite"),
    adminUsername: "admin", adminPassword: "test-password", sessionTtlHours: 12, cookieSecure: false,
    tmuxMode: "disabled", ttydBaseUrl: null, terminalSigningSecret: "test-terminal-secret",
    executionEnvelopeSecret: ENVELOPE_SECRET, repoRoot: process.cwd(), plannerRuntime: "demo-local",
    copilotExecutable: "copilot", copilotModel: null, opencodeExecutable: "opencode", opencodeModel: null,
    safetyOpencodeModel: null, requireModelDiversity: false, approvalTtlMinutes: 30, maxFailedChangesPerHour: 3,
    agentBrokerSocket: null, executorBrokerSocket: null, executorBrokerSecret: null, nodeEnv: "development",
    ...overrides,
  };
}

type Sent = { message_id: number; chat: { id: number }; text: string; reply_markup?: any };

function fakeTelegram() {
  const calls: Array<{ method: string; body: Record<string, any> }> = [];
  const updates: Array<Record<string, unknown>> = [];
  const sent: Sent[] = [];
  let nextId = 300;
  let updateId = 1;
  return {
    calls, updates, sent: () => sent,
    call: async (method: string, body: Record<string, unknown>) => {
      calls.push({ method, body: body as Record<string, any> });
      if (method === "sendMessage") {
        const message = { message_id: nextId++, chat: { id: Number(body.chat_id) }, text: String(body.text).trim(), reply_markup: body.reply_markup };
        sent.push(message);
        return message;
      }
      if (method === "getUpdates") return updates.splice(0).map((update) => ({ update_id: updateId++, ...update }));
      return true;
    },
  };
}

function tap(message: Sent, overrides: { fromId?: number } = {}) {
  return { callback_query: {
    id: `cb-${Math.random()}`, from: { id: overrides.fromId ?? Number(OPERATOR), is_bot: false }, data: message.reply_markup.inline_keyboard[0][0].callback_data,
    message: { message_id: message.message_id, chat: { id: message.chat.id }, text: message.text },
  } };
}

async function setup(options: { role: "box" | "vps" | "lab0"; review?: string; github?: GithubFetch }) {
  const dir = mkdtempSync(path.join(tmpdir(), "telegram-self-update-"));
  cleanup.push(() => rmSync(dir, { recursive: true, force: true }));
  const seed = new CockpitDatabase(path.join(dir, "cockpit.sqlite"));
  seed.initialize();
  seed.seedAdmin("admin", "test-password");
  const owner = seed.createUser("hermes-automation", "unusable-random-password", "automation");
  const bearer = seed.rotateApiToken(owner.id, "hermes", ["POST /api/hermes/runbook", "GET /api/hermes/jobs/:jobId"]);
  const session = seed.upsertSession({ name: "hermes-self-update", ownerId: owner.id, tmuxSessionName: "cockpit-hermes-self-update", tmuxBackend: "tmux", terminalUrl: null });
  seed.close();

  const executorCalls = await listen(path.join(dir, "executor.sock"), (request) => {
    const expected = createHmac("sha256", BROKER_SECRET).update(JSON.stringify(request.payload)).digest("hex");
    if (request.signature !== expected) return { ok: false, error: "invalid request signature" };
    if (request.payload.action === "self.diff") return { ok: true, output: JSON.stringify({ ok: true, action: "self.diff", version: 1, ...diff() }) };
    if (request.payload.action === "self.update") {
      return { ok: true, output: JSON.stringify({
        action: "self.update", ok: true, result: "ok", phase: "awaiting-activation", sha: SHA,
        activation: { delay_seconds: 600, scheduled_at: "2026-11-27T15:00:00Z", status: "scheduled", unit: `wireguard-ops-cockpit-self-update-activate-${SHA.slice(0, 12)}` },
      }) };
    }
    return { ok: false, error: `unexpected action ${request.payload.action}` };
  });
  const plan = [
    "## Required Permissions", "/usr/local/sbin/cockpit-self-update-action", "",
    "```bash", `/usr/local/sbin/cockpit-self-update-action ${SHA}`, "```",
    "## Risk Zone", "yellow", "## Rollback", "self.update the previous commit",
  ].join("\n");
  await listen(path.join(dir, "agent.sock"), (request) => {
    if (request.role === "planner") return { ok: true, output: plan };
    return { ok: true, output: "VERIFICATION_STATUS: passed\nEVIDENCE: deployed, activation scheduled\nREASON: done" };
  });
  const telegram = fakeTelegram();
  let clock = Date.now();
  const app = await createApp({
    config: config(dir, {
      executorBrokerSocket: path.join(dir, "executor.sock"), executorBrokerSecret: BROKER_SECRET,
      agentBrokerSocket: path.join(dir, "agent.sock"), runnerBrokerSocket: path.join(dir, "agent.sock"),
      instanceRole: options.role, telegramApproval: { token: TOKEN, operatorId: OPERATOR },
    }),
    safetyReviewRunner: async () => ({ actorId: "safety-agent", verdict: "passed", summary: "typed self-update only", details: { schemaVersion: "runbook-safety-review/v1" } }),
    updateReviewRunner: async () => options.review ?? G1_HIGH,
    githubFetch: options.github ?? github(),
    telegramCall: telegram.call,
    telegramPollMs: 0,
    telegramNow: () => clock,
  });
  cleanup.push(() => app.close());
  const inspect = new CockpitDatabase(path.join(dir, "cockpit.sqlite"));
  cleanup.push(() => inspect.close());
  const settled = async (jobId: string, from = "running") => {
    const deadline = Date.now() + 10_000;
    while (inspect.getJob(jobId)?.status === from && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 20));
    return inspect.getJob(jobId)!;
  };
  const submit = async () => {
    const created = await app.inject({
      method: "POST", url: "/api/hermes/runbook", headers: { authorization: `Bearer ${bearer}` },
      payload: { intent: "Cockpit-Selbstupdate auf den Merge von PR #128", sessionId: session.id, timeoutMs: 0, operation: "t_efc1d03e", allowedCapabilities: ["self.update"] },
    });
    expect(created.statusCode).toBe(202);
    return settled(created.json().jobId as string);
  };
  const tick = async () => { await (app as unknown as { telegramApprovalTick?: () => Promise<void> }).telegramApprovalTick?.(); };
  const audits = (action: string) => inspect.listAudits(200).filter((audit) => audit.action === action);
  const installs = () => executorCalls.filter((call) => call.payload.action === "self.update");
  return { app, telegram, inspect, settled, submit, tick, audits, installs, advance: (ms: number) => { clock += ms; } };
}

describe("self-update class A through the Cockpit", () => {
  it("offers the stopped self-update on VPS and installs exactly the reviewed diff after Jochen's tap, once", async () => {
    const flow = await setup({ role: "vps" });
    const job = await flow.submit();
    expect(job.status).toBe("blocked_user_approval");
    expect(job.output?.updateReview).toMatchObject({ result: "finding", reported: false, planAllowed: true });

    await flow.tick();
    const [offer] = flow.telegram.sent();
    expect(flow.telegram.sent()).toHaveLength(1);
    expect(offer.chat.id).toBe(Number(OPERATOR));
    expect(offer.text).toContain("Cockpit vps: Freigabe Selbstupdate (Klasse A)");
    expect(offer.text).toContain(`Job: ${job.id}`);
    expect(offer.text).toContain("0123456789ab: #128, Head fedcba987654");
    expect(offer.text).toContain("[G1, high] point 1 (apps/api/src/app.ts:10-12)");
    expect(offer.text).not.toContain(TOKEN);
    expect(flow.audits("hermes.change.telegram_offered")[0].details).toMatchObject({ scope: "self-update" });
    expect(flow.installs()).toHaveLength(0);

    // Another sender changes nothing.
    flow.telegram.updates.push(tap(offer, { fromId: 4242424242 }));
    await flow.tick();
    expect(flow.inspect.getJob(job.id)!.status).toBe("blocked_user_approval");

    flow.telegram.updates.push(tap(offer));
    await flow.tick();
    const finished = await flow.settled(job.id);
    expect(finished.status).toBe("completed");
    expect(flow.installs()).toHaveLength(1);
    const envelope = finished.output?.envelope as Record<string, unknown>;
    expect(envelope).toMatchObject({ operatorApproved: true });
    expect(flow.installs()[0].payload).toMatchObject({ target: SHA, diffSha256: HASH, envelopeDigest: envelope.digest });
    expect(finished.output?.approval).toMatchObject({ decision: "approved", via: { channel: "telegram", fromId: OPERATOR, class: "A", scope: "self-update" } });

    // Replay: the same tap again installs nothing a second time.
    flow.telegram.updates.push(tap(offer));
    await flow.tick();
    expect(flow.installs()).toHaveLength(1);
    expect(flow.audits("hermes.change.telegram_refused").map((audit) => audit.details.reason)).toEqual(["other sender", "already used"]);
    expect(JSON.stringify(flow.inspect.listAudits(200))).not.toContain(TOKEN);
  });

  it("works the same on Lab0 and refuses a tap after the window", async () => {
    const flow = await setup({ role: "lab0" });
    const job = await flow.submit();
    await flow.tick();
    const [offer] = flow.telegram.sent();
    expect(offer.text).toContain("Cockpit lab0: Freigabe Selbstupdate (Klasse A)");
    flow.advance((TELEGRAM_WINDOW_MINUTES + 1) * 60_000);
    flow.telegram.updates.push(tap(offer));
    await flow.tick();
    expect(flow.audits("hermes.change.telegram_refused").map((audit) => audit.details.reason)).toEqual(["window expired"]);
    expect(flow.inspect.getJob(job.id)!.status).toBe("blocked_user_approval");
    expect(flow.installs()).toHaveLength(0);
  });

  it("offers nothing on box, without a verified marker, or for a backup finding: the click stays", async () => {
    const box = await setup({ role: "box" });
    expect((await box.submit()).status).toBe("blocked_user_approval");
    await box.tick();
    expect(box.telegram.sent()).toHaveLength(0);

    const comments = `${REPO}/issues/128/comments?per_page=100`;
    const unmarked = await setup({ role: "vps", github: github({ [comments]: [] }) });
    expect((await unmarked.submit()).status).toBe("blocked_user_approval");
    await unmarked.tick();
    expect(unmarked.telegram.sent()).toHaveLength(0);

    const backups = await setup({ role: "vps", review: answer([["G10", "high", QUOTED]]) });
    expect((await backups.submit()).status).toBe("blocked_user_approval");
    await backups.tick();
    expect(backups.telegram.sent()).toHaveLength(0);
  });
});
