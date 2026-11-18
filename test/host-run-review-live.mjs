#!/usr/bin/env node
// Measures the doorkeeper of the general host door with a real Claude run
// (card t_befe7fc7). Each case in apps/api/test/fixtures/host-run-review-cases.json
// goes the way of a job: parseHostRunManifest → buildHostRunReviewPrompt for the
// instance role → the safety role's workspace AGENTS.md and claude arguments
// from the agent broker → parseHostRunReviewAnswer, verifyHostRunFindings,
// hostRunPolicy. It is not part of `npm test`: it costs a model run per case.
//
// Needs `npm run build` (apps/api/dist) and a logged-in `claude` in PATH.
// Differences to the broker on the host, named so nobody mistakes the run for
// one: the caller's own Claude login and HOME are used (no per-run
// CLAUDE_CONFIG_DIR, no subprocess scrub), and the reviewer's Bash tool sees
// this machine, not the target host.
//
// node test/host-run-review-live.mjs [--role vps|lab0|box] [--case <id>]... [--out <dir>]
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";

process.env.NODE_ENV = "test"; // the broker module starts no server under test
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const hostRun = await import(path.join(root, "apps/api/dist/host-run.js"));
const { redactSecrets } = await import(path.join(root, "apps/api/dist/update-review.js"));
const broker = await import(path.join(root, "apps/agent-broker/src/index.mjs"));

const args = process.argv.slice(2);
const option = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const role = option("--role") || "vps";
const only = args.flatMap((value, i) => (args[i - 1] === "--case" ? [value] : []));
const out = option("--out");
const model = process.env.COCKPIT_CLAUDE_SAFETY_MODEL || "opus";
const fixture = JSON.parse(fs.readFileSync(path.join(root, "apps/api/test/fixtures/host-run-review-cases.json"), "utf8"));
const cases = fixture.cases.filter((item) => only.length === 0 || only.includes(item.id));
if (out) fs.mkdirSync(out, { recursive: true });

const sessions = fs.mkdtempSync(path.join(os.tmpdir(), "doorkeeper-live-"));
const results = [];
for (const item of cases) {
  const plan = `\`\`\`host-run\n${JSON.stringify(item.manifest)}\n\`\`\``;
  const manifest = hostRun.parseHostRunManifest(plan);
  if (!manifest) { results.push({ id: item.id, expect: item.expect, got: "invalid-manifest", ok: false }); continue; }
  const material = hostRun.buildHostRunReviewPrompt(manifest, { role });
  const workspace = broker.createSessionWorkspace({ requestId: randomUUID(), role: "safety" }, sessions);
  const stream = broker.claudeStream();
  const raw = [];
  const started = Date.now();
  const run = await broker.runProcess(process.env.COCKPIT_CLAUDE_EXECUTABLE || "claude",
    broker.claudeArgs(workspace, model, broker.claudeToolsFor("safety")),
    { ...process.env, DISABLE_AUTOUPDATER: "1", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1" },
    workspace, material.prompt, 30 * 60 * 1000, (line) => { if (out && line !== null) raw.push(line); stream.line(line); });
  const parsed = stream.result ? broker.parseClaudeResult(JSON.stringify(stream.result)) : { ok: false, reason: `claude exit ${run.code}, no result` };
  // As the broker and reviewHostRun: a review Claude's safety classifier stopped
  // fails with the count, and what came through stays the answer (card t_9f370d63).
  const safetyStops = broker.claudeSafetyStops(stream.result);
  const outcome = { manifestHash: hostRun.hostRunManifestHash(manifest), complete: material.complete, missing: material.missing, focus: material.focus,
    answer: parsed.ok ? hostRun.verifyHostRunFindings(hostRun.parseHostRunReviewAnswer(redactSecrets(parsed.output)), manifest) : null,
    reviewerError: safetyStops ? `claude's safety classifier stopped the review ${safetyStops} time(s)` : parsed.ok ? null : parsed.reason, safetyStops };
  const policy = hostRun.hostRunPolicy(manifest, outcome);
  const got = policy.status === "ready" ? "pass" : policy.status === "blocked_user_approval" ? "flag" : policy.status;
  const findings = (outcome.answer?.findings || []).map((f) => ({ class: f.class, where: f.where, title: f.title, evidenced: f.evidenced, path: f.path }));
  // A stopped review withholds its class: the flag itself is what is measured.
  const classOk = item.expect !== "flag" || !item.classes || (safetyStops > 0 && got === "flag") || findings.some((f) => f.evidenced && item.classes.includes(f.class));
  const result = { id: item.id, role, expect: item.expect, got, ok: got === item.expect, classOk, seconds: Math.round((Date.now() - started) / 1000),
    model: parsed.model || null, safetyStops, permissionDenials: stream.result?.permission_denials?.length ?? null, toolUses: stream.toolUses, findings, reason: policy.reason };
  results.push(result);
  if (out) {
    fs.writeFileSync(path.join(out, `${item.id}.prompt.md`), material.prompt);
    fs.writeFileSync(path.join(out, `${item.id}.answer.md`), parsed.ok ? parsed.output : `NO ANSWER: ${parsed.reason}`);
    fs.writeFileSync(path.join(out, `${item.id}.result.json`), JSON.stringify(result, null, 2));
    // The whole stream: where a cut-off answer stopped and why (stop_reason).
    fs.writeFileSync(path.join(out, `${item.id}.stream.jsonl`), raw.map((line) => redactSecrets(line)).join("\n") + "\n");
  }
  console.log(`${result.ok && result.classOk ? "OK  " : "FAIL"} ${item.id} expect=${item.expect} got=${got}${safetyStops ? ` stops=${safetyStops}` : ""} ${findings.map((f) => `${f.class}@${f.where}${f.evidenced ? "" : "(unbelegt)"}`).join(" ")} (${result.seconds}s)`);
  fs.rmSync(workspace, { recursive: true, force: true });
}
fs.rmSync(sessions, { recursive: true, force: true });
if (out) fs.writeFileSync(path.join(out, "summary.json"), JSON.stringify(results, null, 2));
const failed = results.filter((item) => !item.ok || !item.classOk);
console.log(`${results.length - failed.length}/${results.length} as expected`);
process.exit(failed.length ? 1 : 0);
