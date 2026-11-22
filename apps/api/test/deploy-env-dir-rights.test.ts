import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// Rechte von /etc/wireguard-ops-cockpit im Deploy-Skript (deploy/lab0/homeserver-cockpit-deploy.sh,
// Block env-dir-rechte; Karte t_6f07b80b, Lab0-Ausfälle 19.11. und 19.–22.11.2026). Der markierte
// Block läuft 1:1 in bash. chown und runuser sind Stubs (der Test läuft nicht als root):
// chown schreibt seine Aufrufe mit, runuser beantwortet `test` für wgops aus WGOPS_CAN.

const SCRIPT = fileURLToPath(new URL("../../../deploy/lab0/homeserver-cockpit-deploy.sh", import.meta.url));

let dir: string;
let envDir: string;

function block(): string {
  const script = readFileSync(SCRIPT, "utf8");
  const start = script.indexOf("# >>> env-dir-rechte");
  const end = script.indexOf("# <<< env-dir-rechte");
  expect(start).toBeGreaterThan(-1);
  expect(end).toBeGreaterThan(start);
  return script.slice(start, end);
}

// wgopsCan: paths for which `runuser -u wgops -- test …` succeeds.
function run(tail: string, wgopsCan: string[] = []) {
  const script = [
    "set -euo pipefail",
    'die() { echo "FEHLER: $*"; exit 1; }',
    `chown() { echo "chown $*" >> "${path.join(dir, "chown.log")}"; }`,
    'runuser() { [ "$1 $2 $3" = "-u wgops --" ] || return 99; shift 3; local p="${!#}"; case " $WGOPS_CAN " in *" $p "*) return 0;; *) return 1;; esac; }',
    block(),
    tail,
  ].join("\n");
  return spawnSync("bash", ["-c", script], {
    encoding: "utf8",
    env: { PATH: process.env.PATH, ENV_DIR: envDir, WGOPS_CAN: wgopsCan.join(" ") },
  });
}

const mode = (file: string) => (statSync(file).mode & 0o7777).toString(8);
const chowns = () => readFileSync(path.join(dir, "chown.log"), "utf8").trim().split("\n");

beforeEach(() => {
  dir = mkdtempSync(path.join(tmpdir(), "deploy-env-dir-"));
  envDir = path.join(dir, "etc-wireguard-ops-cockpit");
  mkdirSync(envDir, { mode: 0o770 });
  for (const name of ["api.env", "agent.env", "forgejo.env", "instance-role.env", "forgejo-ca.crt"]) {
    writeFileSync(path.join(envDir, name), name === "forgejo.env" ? `COCKPIT_FORGEJO_URL=https://10.0.0.1:3443\nCOCKPIT_FORGEJO_CA="${envDir}/forgejo-ca.crt"\n` : "x\n", { mode: 0o660 });
  }
  writeFileSync(path.join(dir, "elsewhere.env"), "x\n", { mode: 0o644 });
  symlinkSync(path.join(dir, "elsewhere.env"), path.join(envDir, "link.env"));
  writeFileSync(path.join(dir, "chown.log"), "");
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("deploy: rights of /etc/wireguard-ops-cockpit", () => {
  it("sets the target: directory 0710 root:wgops, every .env 0600 root:root, the CA 0640 root:wgops, symlinks untouched", () => {
    const out = run("env_dir_rights_apply");
    expect(out.status, out.stderr).toBe(0);
    expect(mode(envDir)).toBe("710");
    for (const name of ["api.env", "agent.env", "forgejo.env", "instance-role.env"]) expect(mode(path.join(envDir, name))).toBe("600");
    expect(mode(path.join(envDir, "forgejo-ca.crt"))).toBe("640");
    expect(mode(path.join(dir, "elsewhere.env"))).toBe("644");
    expect(chowns()).toEqual([
      `chown root:wgops ${envDir}`,
      `chown root:root ${envDir}/agent.env`,
      `chown root:root ${envDir}/api.env`,
      `chown root:root ${envDir}/forgejo.env`,
      `chown root:root ${envDir}/instance-role.env`,
      `chown root:wgops ${envDir}/forgejo-ca.crt`,
    ]);
  });

  it("pre-check passes when wgops traverses the directory and reads the configured CA, but no .env", () => {
    const out = run("env_dir_rights_check && echo GUT", [envDir, `${envDir}/forgejo-ca.crt`]);
    expect(out.status, out.stderr).toBe(0);
    expect(out.stdout.trim()).toBe("GUT");
  });

  it("pre-check names every deviation: no traversal, CA unreadable, a readable .env (the state of 19.11. and of 22.11.)", () => {
    const locked = run("env_dir_rights_check || echo \"rc=$?\"");
    expect(locked.stdout).toContain(`wgops kann ${envDir} nicht durchqueren`);
    expect(locked.stdout).toContain(`wgops kann die CA ${envDir}/forgejo-ca.crt (COCKPIT_FORGEJO_CA) nicht lesen`);
    expect(locked.stdout).toContain("rc=1");
    const open = run("env_dir_rights_check || echo \"rc=$?\"", [envDir, `${envDir}/forgejo-ca.crt`, `${envDir}/api.env`, `${envDir}/forgejo.env`]);
    expect(open.stdout).toContain(`wgops kann ${envDir}/api.env lesen`);
    expect(open.stdout).toContain(`wgops kann ${envDir}/forgejo.env lesen`);
    expect(open.stdout).not.toContain("nicht durchqueren");
    expect(open.stdout).toContain("rc=1");
  });

  it("pre-check without a configured CA asks only for traversal and closed .env files", () => {
    writeFileSync(path.join(envDir, "forgejo.env"), "COCKPIT_FORGEJO_URL=https://10.0.0.1:3443\n");
    const out = run("env_dir_rights_check && echo GUT", [envDir]);
    expect(out.stdout.trim()).toBe("GUT");
  });

  it("the stat copy is the way back: record, apply, restore puts owners and modes back as they were", () => {
    const record = path.join(dir, "env-dir-rechte.vorher");
    const out = run(`env_dir_rights_record "${record}"; env_dir_rights_apply; : > "${path.join(dir, "chown.log")}"; env_dir_rights_restore "${record}"`);
    expect(out.status, out.stderr).toBe(0);
    expect(mode(record)).toBe("600");
    const lines = readFileSync(record, "utf8").trim().split("\n");
    expect(lines).toContain(`770 ${process.getuid!()} ${process.getgid!()} ${envDir}`);
    expect(lines.some((line) => line.endsWith("/link.env"))).toBe(false);
    expect(mode(envDir)).toBe("770");
    for (const name of ["api.env", "forgejo.env", "forgejo-ca.crt"]) expect(mode(path.join(envDir, name))).toBe("660");
    expect(chowns()).toContain(`chown ${process.getuid!()}:${process.getgid!()} ${envDir}/api.env`);
  });

  it("first install: no directory yet, an empty stat copy", () => {
    rmSync(envDir, { recursive: true, force: true });
    const record = path.join(dir, "env-dir-rechte.vorher");
    const out = run(`env_dir_rights_record "${record}"; wc -c < "${record}"`);
    expect(out.status, out.stderr).toBe(0);
    expect(out.stdout.trim()).toBe("0");
  });

  it("the script uses the block: stat copy before the directory target, no 0700 root:root, pre-check before every restart, health wait after", () => {
    const script = readFileSync(SCRIPT, "utf8");
    expect(script).not.toContain('install -d -m 0700 -o root -g root "$ENV_DIR"');
    const record = script.indexOf('env_dir_rights_record "$ENV_RIGHTS_BEFORE"');
    const target = script.indexOf('install -d -m 0710 -o root -g wgops "$ENV_DIR"');
    expect(record).toBeGreaterThan(script.indexOf("# <<< env-dir-rechte"));
    expect(target).toBeGreaterThan(record);
    const apply = script.indexOf("env_dir_rights_apply   #");
    const instanceRole = script.indexOf('install -m 600 -o root -g root "$COCKPIT_DIR/deploy/$COCKPIT_ROLE/instance-role.env" "$ENV_DIR/instance-role.env"');
    const check = script.indexOf('env_rights_problems="$(env_dir_rights_check)"');
    const restart = script.indexOf("# >>> dienste-zyklus");
    expect(apply).toBeGreaterThan(target);
    expect(check).toBeGreaterThan(Math.max(apply, instanceRole));
    expect(restart).toBeGreaterThan(check);
    expect(script.indexOf('api_health_wait "${COCKPIT_DEPLOY_HEALTH_WAIT:-60}"')).toBeGreaterThan(restart);
  });
});
