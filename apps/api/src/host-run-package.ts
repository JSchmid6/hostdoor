import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import https from "node:https";

import { PACKAGE_MAX_BYTES, type HostRunPackage, type HostRunPackageSpec } from "./host-run.js";

// The package of a host run (card t_d7d34cf5, doc/setup/host-run.md 2c): code
// too large for the plan comes from one of the operator's own Forgejo
// repositories at one commit. The Cockpit — not the requester — fetches every
// file, checks it against the sha256 in the manifest and reads the provenance
// (the merged pull request and its comments) for the doorkeeper. What fails
// here is a deterministic stop before the review (incomplete material, nothing
// runs): an owner that is not a package source, no Forgejo configured, a file
// that cannot be read, a sha256 that does not match, a file that is not text.
// Whether the provenance is enough (merged, second review) is the doorkeeper's
// judgement (X5), not a rule here.

export interface ForgejoResponse { status: number; body: Buffer }
// GET of one Forgejo API path (relative to <base>/api/v1). Tests inject a stub.
export type ForgejoFetch = (apiPath: string) => Promise<ForgejoResponse>;

export interface PackageSource {
  fetch: ForgejoFetch | null;
  // Repository owners whose repositories may deliver packages (COCKPIT_PACKAGE_OWNERS).
  owners: string[];
  // Shown to the doorkeeper, never a secret.
  label: string;
}

export type PackageLoad = { pkg: HostRunPackage; problem?: undefined } | { pkg?: undefined; problem: string };

function json(response: ForgejoResponse): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(response.body.toString("utf8"));
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
  } catch { return {}; }
}

function field(value: unknown, ...keys: string[]): unknown {
  return keys.reduce<unknown>((current, key) => (current && typeof current === "object" ? (current as Record<string, unknown>)[key] : undefined), value);
}

// ignoreBOM keeps a byte order mark in the text, so text and bytes stay one-to-one (the helper checks the sha256 of the re-encoded text).
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export async function loadHostRunPackage(spec: HostRunPackageSpec, source: PackageSource): Promise<PackageLoad> {
  const owner = spec.repo.split("/")[0];
  if (!source.fetch) return { problem: "this Cockpit has no Forgejo package source configured (COCKPIT_FORGEJO_URL, COCKPIT_FORGEJO_TOKEN)" };
  if (!source.owners.includes(owner)) return { problem: `${spec.repo} is not a package source of this Cockpit (allowed owners: ${source.owners.join(", ") || "none"})` };
  const repo = `/repos/${spec.repo.split("/").map(encodeURIComponent).join("/")}`;
  const get = source.fetch;
  try {
    const files: HostRunPackage["files"] = [];
    let total = 0;
    for (const file of spec.files) {
      const response = await get(`${repo}/raw/${file.path.split("/").map(encodeURIComponent).join("/")}?ref=${spec.commit}`);
      if (response.status !== 200) return { problem: `${file.path} at ${spec.commit.slice(0, 12)} could not be read from ${spec.repo} (HTTP ${response.status})` };
      const sha256 = createHash("sha256").update(response.body).digest("hex");
      if (sha256 !== file.sha256) return { problem: `${file.path} at ${spec.commit.slice(0, 12)} has sha256 ${sha256}, the manifest names ${file.sha256}` };
      total += response.body.length;
      if (total > PACKAGE_MAX_BYTES) return { problem: `the package is larger than ${PACKAGE_MAX_BYTES} bytes` };
      let text: string;
      try { text = decoder.decode(response.body); } catch { return { problem: `${file.path} is not UTF-8 text; a package carries only reviewable text` }; }
      if (text.includes("\0")) return { problem: `${file.path} contains a NUL byte; a package carries only reviewable text` };
      files.push({ ...file, text, bytes: response.body.length });
    }
    return { pkg: { spec, files, provenance: await provenance(spec, repo, get, source.label) } };
  } catch (error) {
    return { problem: `Forgejo not readable: ${(error instanceof Error ? error.message : "request failed").slice(0, 200)}` };
  }
}

// Facts for the doorkeeper, read from Forgejo by the Cockpit. Each is one line
// (a finding can quote it); comment bodies follow line by line.
async function provenance(spec: HostRunPackageSpec, repo: string, get: ForgejoFetch, label: string): Promise<string[]> {
  const lines: string[] = [];
  const info = await get(repo);
  const defaultBranch = String(field(json(info), "default_branch") || "");
  lines.push(`repository: ${spec.repo} on ${label}, default branch: ${defaultBranch || "(unreadable)"}`);
  lines.push(`commit: ${spec.commit}`);
  const pull = await get(`${repo}/commits/${spec.commit}/pull`);
  const pr = pull.status === 200 ? json(pull) : {};
  const number = field(pr, "number");
  const merged = field(pr, "merged") === true && field(pr, "merge_commit_sha") === spec.commit;
  const base = String(field(pr, "base", "ref") || "");
  const head = String(field(pr, "head", "sha") || "");
  if (typeof number !== "number" || !merged) {
    lines.push("pull request: none — the commit is not the merge commit of a merged pull request");
    return lines;
  }
  lines.push(`pull request: #${number} "${String(field(pr, "title") || "").slice(0, 160)}", merged into ${base}${base === defaultBranch ? " (the default branch)" : " — NOT the default branch"}, merge commit = this commit`);
  lines.push(`reviewed head of #${number}: ${head || "(unreadable)"}`);
  const tree = async (sha: string) => String(field(json(await get(`${repo}/git/commits/${sha}`)), "commit", "tree", "sha") || "");
  const [mergeTree, headTree] = [await tree(spec.commit), head ? await tree(head) : ""];
  lines.push(mergeTree && mergeTree === headTree
    ? "tree of the commit: identical to the reviewed head"
    : "tree of the commit: differs from the reviewed head (the default branch had other changes merged in)");
  const comments = await get(`${repo}/issues/${number}/comments?limit=50`);
  const list = comments.status === 200 ? (() => { try { const value: unknown = JSON.parse(comments.body.toString("utf8")); return Array.isArray(value) ? value : []; } catch { return []; } })() : [];
  lines.push(comments.status === 200 ? `comments on #${number}: ${list.length}` : `comments on #${number}: unreadable (HTTP ${comments.status})`);
  list.forEach((comment, index) => {
    lines.push(`comment ${index + 1} by ${String(field(comment, "user", "login") || "?")} at ${String(field(comment, "created_at") || "?")}:`);
    for (const line of String(field(comment, "body") || "").replace(/\r\n/g, "\n").split("\n")) lines.push(`| ${line}`);
  });
  return lines;
}

// The default reader: Forgejo's API over HTTPS with the operator's CA, a
// read-only token, bounded answers, no redirects.
export function forgejoApiFetch(baseUrl: string, token: string, caFile: string | null, timeoutMs = 15_000): ForgejoFetch {
  const ca = caFile ? readFileSync(caFile) : undefined;
  const base = new URL(baseUrl.replace(/\/+$/, "") + "/api/v1");
  return (apiPath) => new Promise((resolve, reject) => {
    const url = new URL(base.pathname + apiPath, base);
    const request = https.get(url, { ca, headers: { authorization: `token ${token}`, accept: "application/json", "user-agent": "wireguard-ops-cockpit-host-run-package" }, timeout: timeoutMs }, (response) => {
      const chunks: Buffer[] = [];
      let size = 0;
      response.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > 2 * PACKAGE_MAX_BYTES) { request.destroy(new Error(`GET ${apiPath.split("?")[0]} answered more than ${2 * PACKAGE_MAX_BYTES} bytes`)); return; }
        chunks.push(chunk);
      });
      response.on("end", () => resolve({ status: response.statusCode ?? 0, body: Buffer.concat(chunks) }));
      response.on("error", reject);
    });
    request.on("timeout", () => request.destroy(new Error(`GET ${apiPath.split("?")[0]} timed out`)));
    request.on("error", reject);
  });
}
