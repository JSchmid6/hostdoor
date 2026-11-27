import { createHmac } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { createApp } from "../src/app.js";
import type { AppConfig } from "../src/config.js";
import { CockpitDatabase } from "../src/db.js";
import { SECOND_REVIEW_REPOSITORY_PATH, type GithubFetch, type UpdateDiff } from "../src/update-review.js";

// Staging through the Cockpit (card t_1606261a): a self-update whose material
// no review can see completely, without a second review that covers it, gets
// its next stage measured with self.diff; the reviewer is not asked about a
// part, nothing is installed, and the job names the stage as the next step.

const BROKER_SECRET = "executor-broker-test-secret";
const BASE = "89abcdef0123456789abcdef0123456789abcdef";
const HASH = "a".repeat(64);
const REPO = SECOND_REVIEW_REPOSITORY_PATH;
const at = (index: number) => `d${index.toString(16).padStart(39, "0")}`.slice(0, 40);
const TARGET = at(3);
const FILE = "apps/api/src/app.ts";
const cleanup: Array<() => void | Promise<void>> = [];

afterEach(async () => {
  for (const step of cleanup.splice(0).reverse()) await step();
});

// The first-parent line BASE -> at(1) -> at(2) -> at(3), one side commit each.
function github(): GithubFetch {
  const commits: unknown[] = [];
  let parent = BASE;
  for (let index = 1; index <= 3; index += 1) {
    const side = `e${index.toString(16).padStart(39, "0")}`.slice(0, 40);
    commits.push({ sha: side, parents: [{ sha: parent }], commit: { message: `feat: side ${index}` } });
    commits.push({ sha: at(index), parents: [{ sha: parent }, { sha: side }], commit: { message: `Merge pull request #${100 + index} from x/y` } });
    parent = at(index);
  }
  return async (apiPath) => {
    if (apiPath === `${REPO}/compare/${BASE}...${TARGET}`) return { status: "ahead", total_commits: commits.length, commits };
    throw new Error(`GET ${apiPath} answered 404`);
  };
}

// The runner's diff of BASE..sha: complete up to `fitsUpTo` merges, cut by the runner beyond.
function diff(sha: string, fitsUpTo: number): UpdateDiff {
  const cut = parseInt(sha.slice(1), 16) > fitsUpTo;
  return {
    base: BASE, sha, diffSha256: HASH, baseSource: "state", commitSubject: "Merge",
    files: [{ status: "M", path: FILE, added: 1, deleted: 0, class: "focus-hunks" }],
    filesTotal: 1, stat: " 1 file changed, 1 insertion(+)\n",
    focusAreas: [{ kind: "approval-and-auth", guarantees: ["G1"], reason: "approval route", files: [FILE], hunks: [], lockfiles: [], packages: [] }],
    excerpt: [{ path: FILE, text: [`diff --git a/${FILE} b/${FILE}`, `--- a/${FILE}`, `+++ b/${FILE}`, "@@ -10,2 +10,3 @@", "   const job = load();", "+  audit(job);", "   return job;", ""].join("\n") }],
    truncated: cut, partialFiles: cut ? [FILE] : [], omittedFiles: [],
  };
}

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
    executionEnvelopeSecret: "test-envelope-secret", repoRoot: process.cwd(), plannerRuntime: "demo-local",
    copilotExecutable: "copilot", copilotModel: null, opencodeExecutable: "opencode", opencodeModel: null,
    safetyOpencodeModel: null, requireModelDiversity: false, approvalTtlMinutes: 30, maxFailedChangesPerHour: 3,
    agentBrokerSocket: null, executorBrokerSocket: null, executorBrokerSecret: null, nodeEnv: "development",
    ...overrides,
  };
}

async function run(fitsUpTo: number) {
  const dir = mkdtempSync(path.join(tmpdir(), "update-staging-"));
  cleanup.push(() => rmSync(dir, { recursive: true, force: true }));
  const seed = new CockpitDatabase(path.join(dir, "cockpit.sqlite"));
  seed.initialize();
  seed.seedAdmin("admin", "test-password");
  const owner = seed.createUser("hermes-automation", "unusable-random-password", "automation");
  const bearer = seed.rotateApiToken(owner.id, "hermes", ["POST /api/hermes/runbook", "GET /api/hermes/jobs/:jobId"]);
  const session = seed.upsertSession({ name: "hermes-staging", ownerId: owner.id, tmuxSessionName: "cockpit-hermes-staging", tmuxBackend: "tmux", terminalUrl: null });
  seed.close();

  const executorCalls = await listen(path.join(dir, "executor.sock"), (request) => {
    const expected = createHmac("sha256", BROKER_SECRET).update(JSON.stringify(request.payload)).digest("hex");
    if (request.signature !== expected) return { ok: false, error: "invalid request signature" };
    if (request.payload.action === "self.diff") return { ok: true, output: JSON.stringify({ ok: true, action: "self.diff", version: 1, ...diff(request.payload.target, fitsUpTo) }) };
    return { ok: false, error: `unexpected action ${request.payload.action}` };
  });
  const plan = [
    "## Required Permissions", "/usr/local/sbin/cockpit-self-update-action", "",
    "```bash", `/usr/local/sbin/cockpit-self-update-action ${TARGET}`, "```",
    "## Risk Zone", "yellow", "## Rollback", "self.update the previous commit",
  ].join("\n");
  await listen(path.join(dir, "agent.sock"), (request) => request.role === "planner" ? { ok: true, output: plan } : { ok: false, error: "not expected" });
  const reviewed: string[] = [];
  const app = await createApp({
    config: config(dir, {
      executorBrokerSocket: path.join(dir, "executor.sock"), executorBrokerSecret: BROKER_SECRET,
      agentBrokerSocket: path.join(dir, "agent.sock"), runnerBrokerSocket: path.join(dir, "agent.sock"), instanceRole: "lab0",
    }),
    safetyReviewRunner: async () => ({ actorId: "safety-agent", verdict: "passed", summary: "typed self-update only", details: { schemaVersion: "runbook-safety-review/v1" } }),
    updateReviewRunner: async (prompt) => { reviewed.push(prompt); return "VERDICT: approve\nNOTES: fine"; },
    githubFetch: github(),
  });
  cleanup.push(() => app.close());
  const inspect = new CockpitDatabase(path.join(dir, "cockpit.sqlite"));
  cleanup.push(() => inspect.close());
  const created = await app.inject({
    method: "POST", url: "/api/hermes/runbook", headers: { authorization: `Bearer ${bearer}` },
    payload: { intent: "Cockpit-Selbstupdate Lab0 auf main", sessionId: session.id, timeoutMs: 0, operation: "t_1606261a", allowedCapabilities: ["self.update"] },
  });
  expect(created.statusCode).toBe(202);
  const jobId = created.json().jobId as string;
  const deadline = Date.now() + 10_000;
  while (inspect.getJob(jobId)?.status === "running" && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 20));
  const diffs = executorCalls.filter((call) => call.payload.action === "self.diff").map((call) => call.payload.target as string);
  const installs = executorCalls.filter((call) => call.payload.action === "self.update");
  return { job: inspect.getJob(jobId)!, reviewed, diffs, installs };
}

describe("self-update staging through the Cockpit", () => {
  it("measures the next stage, asks no reviewer about a part and installs nothing", async () => {
    const { job, reviewed, diffs, installs } = await run(2);
    expect(job.status).toBe("blocked_prerequisite");
    expect(reviewed).toHaveLength(0);
    expect(installs).toHaveLength(0);
    // The target, then the candidates on the line below it (never the target again).
    expect(diffs).toEqual([TARGET, at(1), at(2)]);
    expect(job.output?.updateReview).toMatchObject({ result: "incomplete", staging: { target: TARGET, stage: { sha: at(2), merges: 2, of: 3 } } });
    const explanation = job.output?.explanation as { neededToContinue: string[] } | undefined;
    const needed = [...((job.output?.policy as { neededToContinue?: string[] })?.neededToContinue ?? []), ...(explanation?.neededToContinue ?? [])];
    expect(needed.some((line) => line.includes(`self.update ${at(2)}`))).toBe(true);
  });

  it("stops honestly and lets the review run as before when not even the first merge fits", async () => {
    const { job, reviewed, installs } = await run(0);
    expect(job.status).toBe("blocked_prerequisite");
    expect(reviewed.length).toBeGreaterThan(0);
    expect(installs).toHaveLength(0);
    expect(job.output?.updateReview).toMatchObject({ result: "incomplete", staging: { target: TARGET, reason: `even the first commit ${at(1).slice(0, 12)} alone does not fit one complete review` } });
  });
});
