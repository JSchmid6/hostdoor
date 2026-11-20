#!/bin/bash
# ============================================================================
# cockpit-dienste-update-action.test.sh — offline harness for the typed
# server-dienste install helper (deploy/helpers/cockpit-dienste-update-action).
#
# Everything happens below one mktemp directory: a fixture repository with a
# stub runner, and a systemd-run stub that logs its arguments and runs the
# command in place. The harness refuses to run unless that directory is a
# fresh one below /tmp or /var/tmp, and it never writes anywhere else.
#
# Call (as root; the owner check needs root-owned fixture files):
#   sudo bash test/cockpit-dienste-update-action.test.sh
# ============================================================================
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
HELPER="$(cd "$HERE/.." && pwd)/deploy/helpers/cockpit-dienste-update-action"
[ "$(id -u)" -eq 0 ] || { echo "FEHLER: bitte als root: sudo bash $0" >&2; exit 2; }
[ -f "$HELPER" ] || { echo "FEHLER: $HELPER fehlt" >&2; exit 2; }

FIX="$(mktemp -d "${TMPDIR:-/tmp}/cockpit-dienste-test.XXXXXX")"
case "$FIX" in
  /tmp/cockpit-dienste-test.*|/var/tmp/cockpit-dienste-test.*) ;;
  *) echo "FEHLER: unerwartetes Fixture-Verzeichnis '$FIX'" >&2; exit 2 ;;
esac
[ -d "$FIX" ] && [ -z "$(ls -A "$FIX")" ] || { echo "FEHLER: Fixture nicht leer" >&2; exit 2; }
trap 'rm -rf -- "$FIX"' EXIT

mkdir -p "$FIX/repo/bin" "$FIX/repo/.git" "$FIX/stub"
chmod 750 "$FIX/repo"
cat > "$FIX/repo/bin/uebernehmen" <<'EOF'
import json, sys
print(json.dumps({"ok": True, "args": sys.argv[1:]}))
sys.exit(7 if sys.argv[1:2] == ["einspielen"] and sys.argv[3] == "f" * 64 else 0)
EOF
chmod 755 "$FIX/repo/bin/uebernehmen"
cat > "$FIX/stub/systemd-run" <<EOF
#!/bin/bash
echo "\$*" >> "$FIX/systemd-run.log"
while [ \$# -gt 0 ]; do case "\$1" in -p) shift 2 ;; --*) shift ;; *) break ;; esac; done
exec "\$@"
EOF
chmod 755 "$FIX/stub/systemd-run"

export COCKPIT_DIENSTE_REPO_DIR="$FIX/repo" COCKPIT_DIENSTE_SYSTEMD_RUN="$FIX/stub/systemd-run"
SHA=0123456789abcdef0123456789abcdef01234567
HASH=$(printf 'e%.0s' $(seq 64))
fails=0
check() { # check <name> <expected-exit> <args...>
  local name="$1" want="$2" got=0; shift 2
  bash "$HELPER" "$@" > "$FIX/out" 2> "$FIX/err" || got=$?
  if [ "$got" -ne "$want" ]; then echo "ROT  $name: exit $got statt $want ($(cat "$FIX/err"))"; fails=$((fails + 1)); else echo "GRÜN $name"; fi
}

check "status läuft den Runner mit stand" 0 status
grep -q '"args": \["stand"\]' "$FIX/out" || { echo "ROT  status-Argumente"; fails=$((fails + 1)); }
check "diff mit voller sha" 0 diff "$SHA"
grep -q "\"args\": \[\"diff\", \"$SHA\"\]" "$FIX/out" || { echo "ROT  diff-Argumente"; fails=$((fails + 1)); }
check "einspielen mit sha und Hash" 0 "$SHA" "$HASH"
grep -q "\"einspielen\", \"$SHA\", \"$HASH\"" "$FIX/out" || { echo "ROT  einspielen-Argumente"; fails=$((fails + 1)); }
check "Exit-Code des Runners kommt durch" 7 "$SHA" "$(printf 'f%.0s' $(seq 64))"
grep -q -- "--wait --collect --pipe" "$FIX/systemd-run.log" || { echo "ROT  systemd-run-Form"; fails=$((fails + 1)); }

check "nackte sha ohne Hash" 65 "$SHA"
check "kurze sha" 65 diff "${SHA:0:12}"
check "Großbuchstaben" 65 "${SHA^^}" "$HASH"
check "Hash zu kurz" 65 "$SHA" "${HASH:1}"
check "Zusatzargument" 64 "$SHA" "$HASH" --force
check "unbekannter Befehl" 64 restart
check "leer" 64

chmod 775 "$FIX/repo/bin"
check "Runner-Ordner gruppen-schreibbar" 67 status
chmod 755 "$FIX/repo/bin"
chown 65534 "$FIX/repo/bin/uebernehmen"
check "Runner gehört nicht root" 67 status
chown 0 "$FIX/repo/bin/uebernehmen"
mv "$FIX/repo/bin/uebernehmen" "$FIX/repo/bin/echt" && ln -s echt "$FIX/repo/bin/uebernehmen"
check "Runner als Symlink" 67 status

# show <path>: read-only review input for the doorkeeper (doc/setup/host-run.md,
# "Code aus geprüften Repos"), against a real git repository.
GITREPO="$FIX/gitrepo"
mkdir -p "$GITREPO/bin" "$GITREPO/deploy/units"
chmod 750 "$GITREPO"
cp "$FIX/repo/bin/echt" "$GITREPO/bin/uebernehmen"
printf '#!/usr/bin/python3\nprint("werkzeug")\n' > "$GITREPO/bin/werkzeug"
printf '[Service]\nExecStart=/opt/server-dienste/bin/werkzeug\n' > "$GITREPO/deploy/units/werkzeug.service"
head -c 70000 /dev/zero | tr '\0' 'x' > "$GITREPO/bin/gross"
chmod 755 "$GITREPO/bin/uebernehmen" "$GITREPO/bin/werkzeug"
git -C "$GITREPO" init -q
git -C "$GITREPO" -c user.name=t -c user.email=t@t add -A
git -C "$GITREPO" -c user.name=t -c user.email=t@t commit -qm stand
GITHEAD="$(git -C "$GITREPO" rev-parse HEAD)"
export COCKPIT_DIENSTE_REPO_DIR="$GITREPO"
field() { python3 -c 'import json,sys; v=json.load(open(sys.argv[1]))[sys.argv[2]]; print(json.dumps(v) if not isinstance(v,str) else v)' "$FIX/out" "$1"; }
expect() { # expect <name> <field> <value>
  local got; got="$(field "$2" 2>/dev/null || echo FEHLT)"
  if [ "$got" = "$3" ]; then echo "GRÜN $1"; else echo "ROT  $1: $2=$got statt $3"; fails=$((fails + 1)); fi
}

check "show: sauberer Stand" 0 show bin/werkzeug
expect "show: head" head "$GITHEAD"
expect "show: gleich HEAD" matchesHead true
expect "show: Baum sauber" treeClean true
expect "show: nicht abgeschnitten" truncated false
expect "show: sha256" sha256 "$(sha256sum "$GITREPO/bin/werkzeug" | cut -d' ' -f1)"
[ "$(field contentBase64 | base64 -d)" = "$(cat "$GITREPO/bin/werkzeug")" ] && echo "GRÜN show: Inhalt" || { echo "ROT  show: Inhalt"; fails=$((fails + 1)); }
check "show: Unit-Datei" 0 show deploy/units/werkzeug.service
expect "show: Unit gleich HEAD" matchesHead true
check "show: große Datei" 0 show bin/gross
expect "show: große Datei abgeschnitten" truncated true
expect "show: große Datei Größe" size 70000
[ "$(field contentBase64 | base64 -d | wc -c)" -eq 65536 ] && echo "GRÜN show: Schnitt bei 65536" || { echo "ROT  show: Schnitt"; fails=$((fails + 1)); }
check "show: fehlt" 0 show bin/gibtsnicht
expect "show: fehlt gemeldet" exists false
echo 'print("anders")' >> "$GITREPO/bin/werkzeug"
check "show: geänderte Datei" 0 show bin/werkzeug
expect "show: geändert ≠ HEAD" matchesHead false
expect "show: Baum schmutzig" treeClean false
expect "show: kein Inhalt geändert" contentBase64 ""
git -C "$GITREPO" checkout -q -- bin/werkzeug
# A tracked path hardlinked to a file outside the repository: its bytes are not
# the blob, so no content (the old form showed the outside file).
printf 'passwort: hunter2\n' > "$FIX/geheim"
mv "$GITREPO/bin/werkzeug" "$FIX/werkzeug.orig" && ln "$FIX/geheim" "$GITREPO/bin/werkzeug"
check "show: Hardlink nach außen" 0 show bin/werkzeug
expect "show: Hardlink ≠ HEAD" matchesHead false
expect "show: kein Inhalt Hardlink" contentBase64 ""
rm "$GITREPO/bin/werkzeug" && mv "$FIX/werkzeug.orig" "$GITREPO/bin/werkzeug"
# core.fsmonitor in the repository's own config is a command git would run as
# root on status; the show path must not run it, nor refresh the index.
printf '#!/bin/sh\ntouch %s\n' "$FIX/fsmonitor-lief" > "$FIX/fsmonitor.sh" && chmod 755 "$FIX/fsmonitor.sh"
git -C "$GITREPO" config core.fsmonitor "$FIX/fsmonitor.sh"
touch -d '2001-01-01' "$GITREPO/.git/index"; index_vorher="$(stat -c %Y "$GITREPO/.git/index")"
touch "$GITREPO/bin/werkzeug"
check "show: mit core.fsmonitor" 0 show bin/werkzeug
expect "show: fsmonitor Baum sauber" treeClean true
[ ! -e "$FIX/fsmonitor-lief" ] && echo "GRÜN show: core.fsmonitor nicht ausgeführt" || { echo "ROT  show: core.fsmonitor ausgeführt"; fails=$((fails + 1)); }
[ "$(stat -c %Y "$GITREPO/.git/index")" = "$index_vorher" ] && echo "GRÜN show: Index unverändert" || { echo "ROT  show: Index aufgefrischt"; fails=$((fails + 1)); }
git -C "$GITREPO" config --unset core.fsmonitor
printf 'neu\n' > "$GITREPO/bin/unversioniert"
check "show: unversionierte Datei" 0 show bin/unversioniert
expect "show: unversioniert ≠ HEAD" matchesHead false
expect "show: kein HEAD-Blob" headBlob ""
expect "show: kein Inhalt unversioniert" contentBase64 ""
ln -s werkzeug "$GITREPO/bin/verweis"
check "show: Symlink" 65 show bin/verweis
ln -s / "$GITREPO/wurzel"
check "show: Symlink im Weg" 65 show wurzel/etc/hostname
check "show: .git" 65 show .git/config
check "show: .." 65 show ../repo/bin/echt
check "show: absolut" 65 show /etc/hostname
check "show: Ordner" 65 show bin
check "show: Leerzeichen" 65 show "bin/a b"
check "show: Zusatzargument" 64 show bin/werkzeug extra

echo
[ "$fails" -eq 0 ] && echo "alles grün" || { echo "$fails rot"; exit 1; }
