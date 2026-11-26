import { createHmac } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import type { JobRecord } from "@wireguard-ops-cockpit/domain";

import { createApp } from "../src/app.js";
import { loadConfig, type AppConfig } from "../src/config.js";
import { CockpitDatabase } from "../src/db.js";
import { hostRunReviewInstructions, parseHostRunReviewAnswer } from "../src/host-run.js";
import { classAEligibility, telegramBotCall, TELEGRAM_WINDOW_MINUTES } from "../src/telegram-approval.js";

// Jochens Ja per Telegram für Klasse A (card t_1e9bc441): the Cockpit offers a
// stopped class-A run on box in its own Telegram chat and approves it on the
// operator's tap. The Telegram Bot API is a fake that records what the Cockpit
// sends and hands out the updates a test puts in; the doorkeeper is the
// injected review runner, the executor a fake broker in the real wire format.
// What is checked: only Jochen's tap on exactly the offered message approves
// exactly the offered plan, once, in its window; everything else changes nothing.

const BROKER_SECRET = "executor-broker-test-secret";
const OPERATOR = "8156515098";
const TOKEN = "123456789:AAH-test-token-for-the-cockpit-bot_0123";
const cleanup: Array<() => void | Promise<void>> = [];

afterEach(async () => {
  for (const step of cleanup.splice(0).reverse()) await step();
});

function listen(socketPath: string, answer: (request: Record<string, any>) => Record<string, unknown>): Promise<Array<Record<string, any>>> {
  const seen: Array<Record<string, any>> = [];
  const server = net.createServer((connection) => {
    let input = "";
    connection.setEncoding("utf8");
    connection.on("data", (chunk) => {
      input += chunk;
      if (!input.includes("\n")) return;
      const request = JSON.parse(input.slice(0, input.indexOf("\n")));
      seen.push(request);
      connection.end(JSON.stringify(answer(request)));
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
    executionEnvelopeSecret: "test-envelope-secret", repoRoot: process.cwd(), plannerRuntime: "demo-local",
    copilotExecutable: "copilot", copilotModel: null, opencodeExecutable: "opencode", opencodeModel: null,
    safetyOpencodeModel: null, requireModelDiversity: false, approvalTtlMinutes: 30, maxFailedChangesPerHour: 3,
    agentBrokerSocket: null, executorBrokerSocket: null, executorBrokerSecret: null, nodeEnv: "development",
    ...overrides,
  };
}

// A throwaway workshop VM: the class-A case.
const vmRun = {
  version: "cockpit-host-run/v1", name: "werkstatt vm", purpose: "create a throwaway VM in pool werkstatt on vmbr1 with a test service", mutates: true,
  steps: [{ name: "create", run: "qm create 150 --name probe --pool werkstatt --net0 virtio,bridge=vmbr1 --scsi0 werkstatt:8,format=qcow2" }],
  checks: [{ name: "exists", run: "qm status 150" }],
  rollback: ["qm stop 150; qm destroy 150"],
  risk: ["contained"],
};
const planWith = (manifest: Record<string, unknown>) => ["```host-run", JSON.stringify(manifest), "```", "## Intent", "Werkstatt-VM anlegen."].join("\n");
const x3 = (classA: string) => [
  "VERDICT: flag",
  "FINDING: new listener in the workshop network",
  "CLASS: X3",
  "WHERE: S1:L1",
  `CODE: ${vmRun.steps[0].run}`,
  "PATH: the new guest becomes reachable inside vmbr1; nothing outside the workshop network changes",
  "SEVERITY: medium",
  `CLASS_A: ${classA}`,
  "CLASS_A_WHY: throwaway VM in pool werkstatt on vmbr1 only, snapshot and destroy as rollback",
].join("\n");

interface FakeTelegram {
  calls: Array<{ method: string; body: Record<string, any> }>;
  updates: Array<Record<string, unknown>>;
  sent: () => Array<{ message_id: number; chat: { id: number }; text: string; reply_markup?: any }>;
  fail: { sendMessage: boolean };
}

function fakeTelegram(): FakeTelegram & { call: (method: string, body: Record<string, unknown>) => Promise<unknown> } {
  const calls: FakeTelegram["calls"] = [];
  const updates: FakeTelegram["updates"] = [];
  const sent: Array<{ message_id: number; chat: { id: number }; text: string; reply_markup?: any }> = [];
  const fail = { sendMessage: false };
  let nextId = 100;
  let updateId = 1;
  return {
    calls, updates, fail, sent: () => sent,
    call: async (method, body) => {
      calls.push({ method, body: body as Record<string, any> });
      if (method === "sendMessage") {
        if (fail.sendMessage) throw new Error("telegram sendMessage: HTTP 502");
        // Telegram trims what it stores; the Cockpit hashes what came back.
        const message = { message_id: nextId++, chat: { id: Number(body.chat_id) }, text: String(body.text).trim(), reply_markup: body.reply_markup };
        sent.push(message);
        return message;
      }
      if (method === "getUpdates") {
        const out = updates.splice(0).map((update) => ({ update_id: updateId++, ...update }));
        return out;
      }
      return true;
    },
  };
}

function tap(message: { message_id: number; chat: { id: number }; text: string; reply_markup?: any }, overrides: { fromId?: number; data?: string; message?: Record<string, unknown>; isBot?: boolean } = {}) {
  const data = overrides.data ?? message.reply_markup.inline_keyboard[0][0].callback_data;
  return { callback_query: {
    id: `cb-${Math.random()}`, from: { id: overrides.fromId ?? Number(OPERATOR), is_bot: overrides.isBot ?? false }, data,
    message: { message_id: message.message_id, chat: { id: message.chat.id }, text: message.text, ...overrides.message },
  } };
}

async function setup(options: { doorkeeper: string; plan?: string; role?: "box" | "vps" | "lab0" | null; telegram?: boolean }) {
  const dir = mkdtempSync(path.join(tmpdir(), "telegram-approval-"));
  cleanup.push(() => rmSync(dir, { recursive: true, force: true }));
  const seed = new CockpitDatabase(path.join(dir, "cockpit.sqlite"));
  seed.initialize();
  seed.seedAdmin("admin", "test-password");
  const owner = seed.createUser("hermes-automation", "unusable-random-password", "automation");
  const bearer = seed.rotateApiToken(owner.id, "hermes", ["POST /api/hermes/runbook", "GET /api/hermes/jobs/:jobId"]);
  const session = seed.upsertSession({ name: "hermes-telegram", ownerId: owner.id, tmuxSessionName: "cockpit-hermes-telegram", tmuxBackend: "tmux", terminalUrl: null });
  seed.close();

  const executorCalls = await listen(path.join(dir, "executor.sock"), (request) => {
    const expected = createHmac("sha256", BROKER_SECRET).update(JSON.stringify(request.payload)).digest("hex");
    if (request.signature !== expected) return { ok: false, error: "invalid request signature" };
    if (request.payload.action === "host.run") return { ok: true, output: JSON.stringify({ status: "started", jobId: request.payload.envelope.jobId }) };
    return { ok: true, output: JSON.stringify({ ok: true, logTail: "created", state: {
      phase: "finished", status: "success", error: null, snapshot: { snapshotId: "snap-1", kind: "host" },
      steps: [{ index: 1, name: "create", status: "success" }], checks: [{ index: 1, name: "exists", status: "passed" }],
    } }) };
  });
  const agentCalls = await listen(path.join(dir, "agent.sock"), (request) => {
    if (request.role === "planner") return { ok: true, output: options.plan ?? planWith(vmRun) };
    return { ok: true, output: "VERIFICATION_STATUS: passed\nEVIDENCE: VM 150 exists\nREASON: done" };
  });
  const telegram = fakeTelegram();
  let clock = Date.now();
  const doorkeeperPrompts: string[] = [];
  const app = await createApp({
    config: config(dir, {
      executorBrokerSocket: path.join(dir, "executor.sock"), executorBrokerSecret: BROKER_SECRET,
      agentBrokerSocket: path.join(dir, "agent.sock"), runnerBrokerSocket: path.join(dir, "agent.sock"),
      instanceRole: options.role === undefined ? "box" : options.role,
      telegramApproval: options.telegram === false ? null : { token: TOKEN, operatorId: OPERATOR },
    }),
    hostRunReviewRunner: async (prompt) => { doorkeeperPrompts.push(prompt); return options.doorkeeper; },
    hostRunPollMs: 10,
    telegramCall: telegram.call,
    telegramPollMs: 0,
    telegramNow: () => clock,
  });
  cleanup.push(() => app.close());
  const login = await app.inject({ method: "POST", url: "/api/auth/login", payload: { username: "admin", password: "test-password" } });
  const cookie = String(login.headers["set-cookie"]).split(";")[0];
  const inspect = new CockpitDatabase(path.join(dir, "cockpit.sqlite"));
  cleanup.push(() => inspect.close());
  const settled = async (jobId: string) => {
    const deadline = Date.now() + 10_000;
    while (inspect.getJob(jobId)?.status === "running" && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 20));
    return inspect.getJob(jobId)!;
  };
  const submit = async () => {
    const created = await app.inject({ method: "POST", url: "/api/hermes/runbook", headers: { authorization: `Bearer ${bearer}` }, payload: { intent: "Werkstatt-VM fuer den Agent-Browser anlegen", sessionId: session.id, timeoutMs: 0, operation: "t_46caf5c5" } });
    expect(created.statusCode).toBe(202);
    return settled(created.json().jobId as string);
  };
  const tick = async () => { await (app as unknown as { telegramApprovalTick?: () => Promise<void> }).telegramApprovalTick?.(); };
  const audits = (action: string) => inspect.listAudits(200).filter((audit) => audit.action === action);
  return { app, cookie, bearer, telegram, executorCalls, agentCalls, doorkeeperPrompts, inspect, settled, submit, tick, audits, advance: (ms: number) => { clock += ms; } };
}

describe("doorkeeper class A (box only)", () => {
  it("asks for class A only on box and never lets it change the verdict", () => {
    expect(hostRunReviewInstructions("box")).toContain("CLASS_A: yes | no");
    expect(hostRunReviewInstructions("box")).toContain("Class A does not change your VERDICT or your findings");
    expect(hostRunReviewInstructions("vps")).not.toContain("CLASS_A");
    expect(hostRunReviewInstructions("lab0")).not.toContain("CLASS_A");
    expect(hostRunReviewInstructions(null)).not.toContain("CLASS_A");
  });

  it("reads yes only from exactly one plain CLASS_A: yes line", () => {
    expect(parseHostRunReviewAnswer("VERDICT: pass\nCLASS_A: yes\nCLASS_A_WHY: pool werkstatt").classA).toEqual({ value: "yes", why: "pool werkstatt" });
    expect(parseHostRunReviewAnswer("VERDICT: pass\nCLASS_A: **yes**").classA?.value).toBe("yes");
    expect(parseHostRunReviewAnswer("VERDICT: pass\nCLASS_A: no").classA?.value).toBe("no");
    expect(parseHostRunReviewAnswer("VERDICT: pass\nCLASS_A: yes | no").classA?.value).toBe("no");
    expect(parseHostRunReviewAnswer("VERDICT: pass\nCLASS_A: yes, but not quite").classA?.value).toBe("no");
    expect(parseHostRunReviewAnswer("VERDICT: pass\nCLASS_A: yes\nCLASS_A: yes").classA?.value).toBe("no");
    expect(parseHostRunReviewAnswer("VERDICT: pass\nCLASS_A: ja").classA?.value).toBe("no");
    expect(parseHostRunReviewAnswer("VERDICT: pass").classA).toBeUndefined();
    // A quote inside a code fence is the material, not the doorkeeper's line.
    expect(parseHostRunReviewAnswer("VERDICT: pass\n```\nCLASS_A: yes\n```").classA).toBeUndefined();
    // CLASS_A is not the finding's CLASS.
    const flagged = parseHostRunReviewAnswer(x3("yes"));
    expect(flagged.verdict).toBe("flag");
    expect(flagged.findings[0].class).toBe("X3");
    expect(flagged.classA?.value).toBe("yes");
  });
});

describe("telegram approval settings", () => {
  const env = { COCKPIT_TELEGRAM_APPROVAL: "on", COCKPIT_TELEGRAM_BOT_TOKEN: TOKEN, COCKPIT_TELEGRAM_OPERATOR_ID: OPERATOR };
  it("switches on only with the switch, a bot token and a numeric operator id", () => {
    expect(loadConfig(env).telegramApproval).toEqual({ token: TOKEN, operatorId: OPERATOR });
    expect(loadConfig({ ...env, COCKPIT_TELEGRAM_APPROVAL: "off" }).telegramApproval).toBeNull();
    expect(loadConfig({ ...env, COCKPIT_TELEGRAM_APPROVAL: undefined }).telegramApproval).toBeNull();
    expect(loadConfig({ ...env, COCKPIT_TELEGRAM_BOT_TOKEN: "" }).telegramApproval).toBeNull();
    expect(loadConfig({ ...env, COCKPIT_TELEGRAM_BOT_TOKEN: "not-a-token" }).telegramApproval).toBeNull();
    expect(loadConfig({ ...env, COCKPIT_TELEGRAM_OPERATOR_ID: "@jochen" }).telegramApproval).toBeNull();
  });

  it("never puts the token into an error", async () => {
    const call = telegramBotCall(TOKEN, (async () => new Response(JSON.stringify({ ok: false, description: `Unauthorized ${TOKEN}` }), { status: 401 })) as typeof fetch);
    const error = await call("getUpdates", {}).catch((caught: Error) => caught);
    expect(String(error)).toContain("HTTP 401");
    expect(String(error)).not.toContain(TOKEN);
    const down = telegramBotCall(TOKEN, (async () => { throw new Error(`connect failed https://api.telegram.org/bot${TOKEN}/getUpdates`); }) as typeof fetch);
    const network = await down("getUpdates", {}).catch((caught: Error) => caught);
    expect(String(network)).not.toContain(TOKEN);
  });
});

describe("telegram approval for class A", () => {
  it("offers a stopped class-A run in the Cockpit's own chat and runs exactly that plan after Jochen's tap", async () => {
    const flow = await setup({ doorkeeper: x3("yes") });
    const job = await flow.submit();
    expect(job.status).toBe("blocked_user_approval");
    expect(flow.doorkeeperPrompts[0]).toContain("CLASS_A: yes | no");

    await flow.tick();
    const offer = flow.telegram.sent();
    expect(offer).toHaveLength(1);
    expect(offer[0].chat.id).toBe(Number(OPERATOR));
    expect(offer[0].text).toContain(`Job: ${job.id}`);
    expect(offer[0].text).toContain("Vorgang (Angabe James): t_46caf5c5");
    expect(offer[0].text).toContain("Klasse A: throwaway VM in pool werkstatt");
    expect(offer[0].text).not.toContain(TOKEN);
    expect(flow.telegram.calls.find((call) => call.method === "sendMessage")!.body.parse_mode).toBeUndefined();
    expect(flow.audits("hermes.change.telegram_offered")).toHaveLength(1);
    // James sees that the offer went out.
    const seen = await flow.app.inject({ method: "GET", url: `/api/hermes/jobs/${job.id}`, headers: { authorization: `Bearer ${flow.bearer}` } });
    expect(seen.json().job.telegramOffer).toMatchObject({ usedAt: null });
    // One offer per job, also on the next tick.
    await flow.tick();
    expect(flow.telegram.sent()).toHaveLength(1);
    expect(flow.executorCalls.some((call) => call.payload.action === "host.run")).toBe(false);

    flow.telegram.updates.push(tap(offer[0]));
    await flow.tick();
    const finished = await flow.settled(job.id);
    expect(finished.status).toBe("completed");
    const start = flow.executorCalls.find((call) => call.payload.action === "host.run")!;
    expect(start.payload.envelope).toMatchObject({ operatorApproved: true, manifestHash: (job.output?.envelope as Record<string, unknown>).manifestHash });
    expect(start.payload.manifest).toEqual(job.output?.hostRun);
    expect(finished.output?.approval).toMatchObject({ decision: "approved", via: { channel: "telegram", fromId: OPERATOR, messageId: offer[0].message_id, class: "A" } });
    const approved = flow.audits("hermes.change.approved");
    expect(approved).toHaveLength(1);
    expect(approved[0].details).toMatchObject({ via: { channel: "telegram" } });
    expect(JSON.stringify(flow.inspect.listAudits(200))).not.toContain(TOKEN);

    // Replay: the same tap again changes nothing and runs nothing a second time.
    flow.telegram.updates.push(tap(offer[0]));
    await flow.tick();
    expect(flow.executorCalls.filter((call) => call.payload.action === "host.run")).toHaveLength(1);
    expect(flow.audits("hermes.change.telegram_refused").map((audit) => audit.details.reason)).toEqual(["already used"]);
  });

  it("refuses a forged tap: another sender, another chat, another message, an edited message, a made-up button", async () => {
    const flow = await setup({ doorkeeper: x3("yes") });
    const job = await flow.submit();
    await flow.tick();
    const [offer] = flow.telegram.sent();
    const nonce = offer.reply_markup.inline_keyboard[0][0].callback_data;
    flow.telegram.updates.push(
      tap(offer, { fromId: 4242424242 }),
      tap(offer, { isBot: true }),
      tap(offer, { message: { chat: { id: 4242424242 } } }),
      tap(offer, { message: { message_id: offer.message_id + 7 } }),
      tap(offer, { message: { edit_date: 1795680000 } }),
      tap(offer, { message: { text: `${offer.text} (harmlos)` } }),
      tap(offer, { data: "ja:AAAAAAAAAAAAAAAAAAAAAAAA" }),
      tap(offer, { data: `${nonce}x` }),
      // A plain message "Ja <job>" is no approval: messages are not even read.
      { message: { message_id: 999, chat: { id: Number(OPERATOR) }, from: { id: Number(OPERATOR) }, text: `Ja ${job.id}` } },
    );
    await flow.tick();
    expect(flow.audits("hermes.change.telegram_refused").map((audit) => audit.details.reason).sort()).toEqual([
      "not the offer message", "not the offer message", "offer message changed", "offer message changed",
      "other sender", "other sender", "unknown button", "unknown offer",
    ].sort());
    expect(flow.inspect.getJob(job.id)!.status).toBe("blocked_user_approval");
    expect(flow.executorCalls.some((call) => call.payload.action === "host.run")).toBe(false);
    expect(flow.audits("hermes.change.approved")).toHaveLength(0);
    // The real tap still works afterwards: a refusal does not use the offer up.
    flow.telegram.updates.push(tap(offer));
    await flow.tick();
    expect((await flow.settled(job.id)).status).toBe("completed");
  });

  it("refuses a tap after the window and leaves the Cockpit click", async () => {
    const flow = await setup({ doorkeeper: x3("yes") });
    const job = await flow.submit();
    await flow.tick();
    const [offer] = flow.telegram.sent();
    flow.advance((TELEGRAM_WINDOW_MINUTES + 1) * 60_000);
    flow.telegram.updates.push(tap(offer));
    await flow.tick();
    expect(flow.audits("hermes.change.telegram_refused").map((audit) => audit.details.reason)).toEqual(["window expired"]);
    expect(flow.inspect.getJob(job.id)!.status).toBe("blocked_user_approval");
    expect(flow.executorCalls.some((call) => call.payload.action === "host.run")).toBe(false);
    const approved = await flow.app.inject({ method: "POST", url: `/api/hermes/jobs/${job.id}/approval`, headers: { cookie: flow.cookie }, payload: { decision: "approved", reason: "im Cockpit gelesen" } });
    expect(approved.statusCode).toBe(202);
    expect((await flow.settled(job.id)).status).toBe("completed");
  });

  it("refuses when the job changed after the offer (another plan under the same offer)", async () => {
    const flow = await setup({ doorkeeper: x3("yes") });
    const job = await flow.submit();
    await flow.tick();
    const [offer] = flow.telegram.sent();
    // Drift: someone swaps the stored plan; the envelope no longer matches.
    const stored = flow.inspect.getJob(job.id)!;
    flow.inspect.updateJob(job.id, { status: "blocked_user_approval", output: { ...stored.output, plan: `${String(stored.output?.plan)}\nrm -rf /srv` }, completedAt: stored.completedAt });
    flow.telegram.updates.push(tap(offer));
    await flow.tick();
    const reasons = flow.audits("hermes.change.telegram_refused").map((audit) => String(audit.details.reason));
    expect(reasons).toHaveLength(1);
    expect(reasons[0]).toContain("reviewed plan drift");
    expect(flow.executorCalls.some((call) => call.payload.action === "host.run")).toBe(false);
  });

  it("offers nothing outside class A: doorkeeper says no, another finding class, a declared risk beyond exposure, not box, switched off", async () => {
    const no = await setup({ doorkeeper: x3("no") });
    expect((await no.submit()).status).toBe("blocked_user_approval");
    await no.tick();
    expect(no.telegram.sent()).toHaveLength(0);

    const x2 = await setup({ doorkeeper: x3("yes").replace("CLASS: X3", "CLASS: X2") });
    expect((await x2.submit()).status).toBe("blocked_user_approval");
    await x2.tick();
    expect(x2.telegram.sent()).toHaveLength(0);

    const risky = await setup({ doorkeeper: "VERDICT: pass\nCLASS_A: yes\nCLASS_A_WHY: werkstatt", plan: planWith({ ...vmRun, risk: ["data_loss"] }) });
    expect((await risky.submit()).status).toBe("blocked_user_approval");
    await risky.tick();
    expect(risky.telegram.sent()).toHaveLength(0);

    // exposure inside vmbr1 with a pass and CLASS_A yes is class A (risk bolt only).
    const exposure = await setup({ doorkeeper: "VERDICT: pass\nCLASS_A: yes\nCLASS_A_WHY: werkstatt", plan: planWith({ ...vmRun, risk: ["exposure"] }) });
    expect((await exposure.submit()).status).toBe("blocked_user_approval");
    await exposure.tick();
    expect(exposure.telegram.sent()).toHaveLength(1);

    const vps = await setup({ doorkeeper: x3("yes"), role: "vps" });
    expect((await vps.submit()).status).toBe("blocked_user_approval");
    expect(vps.doorkeeperPrompts[0]).not.toContain("CLASS_A");
    await vps.tick();
    expect(vps.telegram.calls).toHaveLength(0);

    const off = await setup({ doorkeeper: x3("yes"), telegram: false });
    expect((await off.submit()).status).toBe("blocked_user_approval");
    await off.tick();
    expect(off.telegram.calls).toHaveLength(0);
    const health = await off.app.inject({ method: "GET", url: "/api/health" });
    expect(health.json().security.telegramApproval).toBe(false);
  });

  it("tries a failed offer again later instead of at every tick", async () => {
    const flow = await setup({ doorkeeper: x3("yes") });
    await flow.submit();
    flow.telegram.fail.sendMessage = true;
    await flow.tick();
    await flow.tick();
    expect(flow.telegram.calls.filter((call) => call.method === "sendMessage")).toHaveLength(1);
    flow.telegram.fail.sendMessage = false;
    flow.advance(6 * 60_000);
    await flow.tick();
    expect(flow.telegram.sent()).toHaveLength(1);
  });
});

describe("class A eligibility", () => {
  const base = (output: Record<string, unknown>, status: JobRecord["status"] = "blocked_user_approval") => ({
    id: "j1", sessionId: "s1", kind: "runbook", subjectId: "hermes-change", status, requiresApproval: false, approvalId: null,
    output, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), completedAt: null,
  }) as unknown as JobRecord;
  const output = () => ({
    hostRun: vmRun, capabilities: ["host.run"], policy: { status: "blocked_user_approval" },
    envelope: { expiresAt: new Date(Date.now() + 600_000).toISOString() },
    safety: { details: { schemaVersion: "host-run-review/v1", complete: true, safetyStops: 0, reviewerError: null, verdict: "flag", reviewedFiles: [], findings: [{ class: "X3", evidenced: true }], classA: { value: "yes", why: "w" } } },
  });
  it("needs every structural fact, not just the doorkeeper's yes", () => {
    expect(classAEligibility(base(output()), "box")).toMatchObject({ eligible: true, reasons: [] });
    const withDetails = (patch: Record<string, unknown>) => { const value = output(); Object.assign(value.safety.details, patch); return base(value); };
    expect(classAEligibility(withDetails({ safetyStops: 1 }), "box").eligible).toBe(false);
    expect(classAEligibility(withDetails({ complete: false }), "box").eligible).toBe(false);
    expect(classAEligibility(withDetails({ findings: [{ class: "X3" }, { class: "X1", evidenced: false }] }), "box").eligible).toBe(false);
    expect(classAEligibility(withDetails({ reviewedFiles: [{ path: "x" }] }), "box").eligible).toBe(false);
    expect(classAEligibility(withDetails({ classA: { value: "no" } }), "box").eligible).toBe(false);
    expect(classAEligibility(withDetails({ classA: null }), "box").eligible).toBe(false);
    expect(classAEligibility(base({ ...output(), breaker: { closesAt: "x" } }), "box").eligible).toBe(false);
    expect(classAEligibility(base({ ...output(), updateReview: {} }), "box").eligible).toBe(false);
    expect(classAEligibility(base({ ...output(), manifest: {} }), "box").eligible).toBe(false);
    expect(classAEligibility(base({ ...output(), hostRun: { ...vmRun, package: { repository: "a/b" } } }), "box").eligible).toBe(false);
    expect(classAEligibility(base({ ...output(), hostRun: { ...vmRun, risk: ["identity_or_secret"] } }), "box").eligible).toBe(false);
    expect(classAEligibility(base({ ...output(), envelope: { expiresAt: new Date(Date.now() - 1).toISOString() } }), "box").eligible).toBe(false);
    expect(classAEligibility(base({ ...output(), envelope: { expiresAt: new Date(Date.now() + 600_000).toISOString(), operatorApproved: true } }), "box").eligible).toBe(false);
    expect(classAEligibility(base(output(), "running"), "box").eligible).toBe(false);
    expect(classAEligibility(base(output()), "lab0").eligible).toBe(false);
    expect(classAEligibility(base(output()), null).eligible).toBe(false);
    expect(classAEligibility(null, "box").eligible).toBe(false);
  });
});
