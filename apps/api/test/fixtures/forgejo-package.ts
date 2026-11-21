import { createHash } from "node:crypto";

import type { ForgejoFetch } from "../../src/host-run-package.js";

// A fake Forgejo for the package of a host run (host-run-package.ts): one
// repository Jochen/lab0-infra, one merged pull request #16 whose merge commit
// is PACKAGE_COMMIT, one second-review comment. Options change single answers.

export const PACKAGE_COMMIT = "54c15b755348702cac98d324035ab7b263ee7003";
export const PACKAGE_HEAD = "42102f90002d62aa7024bc4a18e6daebc87591db";
export const PACKAGE_BRANCH_COMMIT = "a330bb5000000000000000000000000000000000";

export const PACKAGE_CONTENT: Record<string, string> = {
  "dienstwart/install.sh": "#!/bin/bash\nset -eu\necho installing dienstwart\n",
  "dienstwart/registry.json": "{\"dienste\": []}\n",
};

export const sha256 = (text: string | Buffer) => createHash("sha256").update(text).digest("hex");

export const PACKAGE_FILES = Object.entries(PACKAGE_CONTENT).map(([path, text]) => ({ path, sha256: sha256(text) }));

export interface FakeForgejoOptions {
  // Content served instead of the real one (a file that changed).
  content?: Record<string, string>;
  // No merged pull request has the commit as its merge commit.
  unmerged?: boolean;
  comments?: Array<{ login: string; body: string }>;
}

export function fakeForgejo(options: FakeForgejoOptions = {}): { fetch: ForgejoFetch; calls: string[] } {
  const calls: string[] = [];
  const content = { ...PACKAGE_CONTENT, ...options.content };
  const ok = (value: unknown) => ({ status: 200, body: Buffer.from(JSON.stringify(value)) });
  const missing = { status: 404, body: Buffer.from("{\"message\":\"not found\"}") };
  const fetch: ForgejoFetch = async (apiPath) => {
    calls.push(apiPath);
    const [route, query = ""] = apiPath.split("?");
    const repo = "/repos/Jochen/lab0-infra";
    if (route === repo) return ok({ full_name: "Jochen/lab0-infra", default_branch: "main" });
    if (route.startsWith(`${repo}/raw/`)) {
      const file = decodeURIComponent(route.slice(`${repo}/raw/`.length));
      const ref = new URLSearchParams(query).get("ref");
      return file in content && (ref === PACKAGE_COMMIT || ref === PACKAGE_BRANCH_COMMIT) ? { status: 200, body: Buffer.from(content[file]) } : missing;
    }
    if (route === `${repo}/commits/${PACKAGE_COMMIT}/pull` && !options.unmerged) {
      return ok({ number: 16, title: "dienstwart", merged: true, merge_commit_sha: PACKAGE_COMMIT, base: { ref: "main" }, head: { sha: PACKAGE_HEAD } });
    }
    if (route.endsWith("/pull")) return missing;
    if (route === `${repo}/git/commits/${PACKAGE_COMMIT}`) return ok({ commit: { tree: { sha: "tree-merge" } } });
    if (route === `${repo}/git/commits/${PACKAGE_HEAD}`) return ok({ commit: { tree: { sha: "tree-head" } } });
    if (route === `${repo}/issues/16/comments`) {
      const comments = options.comments ?? [{ login: "Jochen", body: `Zweitprüfung (Karte t_bb9bb19e, Opus): FREIGABE\nGeprüft und getestet auf ${PACKAGE_HEAD}.` }];
      return ok(comments.map((comment, index) => ({ id: index + 1, user: { login: comment.login }, created_at: "2026-11-18T17:23:40+01:00", body: comment.body })));
    }
    return missing;
  };
  return { fetch, calls };
}
