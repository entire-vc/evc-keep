#!/usr/bin/env bash
# Red runs of the rotation testbed (docs/rotation-testbed.md).
#
# In a scratch copy of the tree the server's rotation engine is changed so that
# the gates before the old version is revoked wait for no carrier at all
# (they only require that there is some). The stand is then run from that copy:
# scenario 2 must FAIL. In a second copy the host image keeps the machine id
# the package install wrote, so both hosts share it: the hosts check must FAIL.
# In a third the server verifies a systemd-credential carrier without the
# credential name of its last deploy: scenario 1 must FAIL with verify_failed,
# and the carrier that failed must be a3, the systemd credential. On the stand
# the clean copy leaves running, host-a's systemd-creds is changed by a byte,
# then a3's file is replaced by a ciphertext bound to no name, by one bound to
# another name, and by its plaintext (each restored afterwards): `receipt` must
# refuse each and name the broken property. The two jq filters on a3 and the
# rollback filter of scenario 2 are read from rotation.sh and each of their
# terms is shown failing on its own; the clean run must have printed the
# rollback check, so a check_failed that no longer calls it is red too. So are
# the version table of scenario 2 (ON_PREVIOUS) and the two tamper checks. Two
# more copies change rotation.sh itself: in one `tamper` writes a1's own value
# back instead of a wrong one, and `all` must FAIL the tamper "before" check; in
# the other the saved copy is never put back, and `all` must FAIL the "after" one.
# The same procedure on an untouched copy must PASS, so a stand that fails for
# any other reason is not mistaken for a caught mutation.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
SRC=$(cd "$HERE/../.." && pwd)
python3 "$HERE/check-tamper-restore.py"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/keep-testbed-mutation.XXXXXX")
# Every stand goes on exit, also on an interrupt: after the plaintext probe the
# clean stand holds a stand value in the clear until it is removed.
# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
  for p in clean mutant hosts credunit tsame tkeep; do TESTBED_PROJECT="keep-testbed-$p" docker compose -f "$HERE/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

copy() { # copy DIR
  mkdir -p "$1"
  (cd "$SRC" && git ls-files -co --exclude-standard | grep -v '^scripts/testbed/out/' | tar -T - -cf -) | tar -x -C "$1"
}

run() { # run NAME DIR: the whole stand from DIR, in its own compose project
  TESTBED_PROJECT="keep-testbed-$1" TESTBED_OUT="$WORK/$1-out" "$2/scripts/testbed/rotation.sh" all >"$WORK/$1.log" 2>&1
}

mutate() { # mutate DIR: the gates no longer wait for the carriers
  local f="$1/internal/rotation/store.go"
  python3 - "$f" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
a = "return err == nil && total > 0 && total == ok, err"
b = "return err == nil && total > 0 && total == good, err"
if a not in s or b not in s:
    sys.exit("the mutated lines are not where this check expects them")
s = s.replace(a, "return err == nil && total > 0, err").replace(b, "return err == nil && total > 0, err")
open(p, "w").write(s)
PY
  if cmp -s "$f" "$SRC/internal/rotation/store.go"; then echo "the mutation changed nothing"; exit 1; fi
}

mutate_hosts() { # mutate_hosts DIR: the host image keeps the machine id it was built with
  local f="$1/scripts/testbed/Dockerfile"
  python3 - "$f" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
a = " \\\n && : >/etc/machine-id && ln -sf /etc/machine-id /var/lib/dbus/machine-id\n"
if s.count(a) != 1:
    sys.exit("the machine id reset is not where this check expects it")
open(p, "w").write(s.replace(a, "\n"))
PY
  if cmp -s "$f" "$SRC/scripts/testbed/Dockerfile"; then echo "the mutation changed nothing"; exit 1; fi
}

mutate_credunit() { # mutate_credunit DIR: verify forgets the credential name of the last deploy
  local f="$1/internal/deployment/verify.go"
  python3 - "$f" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
a = "c.target.Unit = last.Unit"
if s.count(a) != 1:
    sys.exit("the credential name assignment is not where this check expects it")
open(p, "w").write(s.replace(a, "_ = last"))
PY
  if cmp -s "$f" "$SRC/internal/deployment/verify.go"; then echo "the mutation changed nothing"; exit 1; fi
}

# probe_sealed HOW: on the clean stand one property of a3 is broken (tool: the
# systemd-creds binary no longer matches its package; unbound: the file is
# re-encrypted with no credential name; othername: re-encrypted under another
# name; plaintext: the file is the value itself), then `receipt` must fail on
# the a3 line AND report exactly the fields that probe changes, all others as on
# a sound carrier. The original file (and binary) are put back after each probe.
probe_sealed() {
  local how=$1 cmd want
  local sound='.tool_as_shipped == true and .value_in_file == false and .decrypts_under_its_name == true and .decrypts_under_another_name == false'
  local dec='systemd-creds decrypt --name=api_token /root/a3.cred.orig /srv/app/a3/plain'
  case "$how" in
    tool)      cmd='cp -p /usr/bin/systemd-creds /root/systemd-creds.orig && printf x >>/usr/bin/systemd-creds'
               want=${sound/.tool_as_shipped == true/.tool_as_shipped == false} ;;
    unbound)   cmd="$dec && systemd-creds encrypt --name= /srv/app/a3/plain /srv/app/a3/probe && mv /srv/app/a3/probe /srv/app/a3/api_token.cred"
               want=${sound/.decrypts_under_another_name == false/.decrypts_under_another_name == true} ;;
    othername) cmd="$dec && systemd-creds encrypt --name=api_token-x /srv/app/a3/plain /srv/app/a3/probe && mv /srv/app/a3/probe /srv/app/a3/api_token.cred"
               want=${sound/.decrypts_under_its_name == true/.decrypts_under_its_name == false} ;;
    plaintext) cmd="$dec && mv /srv/app/a3/plain /srv/app/a3/api_token.cred"
               want='.tool_as_shipped == true and .value_in_file == true and .decrypts_under_its_name == false and .decrypts_under_another_name == false' ;;
  esac
  [ "$want" != "$sound" ] || { echo "FAIL: the $how probe expects a sound carrier"; return 1; }
  # Nothing of what systemd-creds says reaches this terminal; the plaintext
  # temporary files go whatever happens.
  if ! TESTBED_PROJECT=keep-testbed-clean docker compose --progress quiet -f "$HERE/compose.yaml" exec -T host-a sh -c \
    "umask 077; cp -p /srv/app/a3/api_token.cred /root/a3.cred.orig || exit 1; rc=0
     { $cmd; } >/dev/null 2>&1 || rc=1; rm -f /srv/app/a3/plain /srv/app/a3/probe; exit \$rc" </dev/null; then
    echo "FAIL: the $how probe could not be set up on host-a"; return 1
  fi
  if TESTBED_PROJECT=keep-testbed-clean TESTBED_OUT="$WORK/clean-out" "$WORK/clean/scripts/testbed/rotation.sh" receipt >"$WORK/probe-$how.json" 2>"$WORK/probe-$how.log"; then
    echo "FAIL: a3 with a broken $how passed the receipt: the sealed check cannot fail"; return 1
  elif grep -q '^FAIL a3: sealed' "$WORK/probe-$how.log" && jq -e ".sealed_carriers[0] | $want" "$WORK/clean-out/receipt.json" >/dev/null; then
    echo "a3 $how: the receipt FAILS as required: $(jq -c '.sealed_carriers[0]|{tool_as_shipped,value_in_file,decrypts_under_its_name,decrypts_under_another_name}' "$WORK/clean-out/receipt.json")"
  else
    echo "FAIL: the $how probe failed, but not on the property it broke:"; tail -15 "$WORK/probe-$how.log"
    jq -c '.sealed_carriers' "$WORK/clean-out/receipt.json" 2>/dev/null || true; return 1
  fi
  # Put a3 back as it was, so the next probe starts from a sound carrier.
  TESTBED_PROJECT=keep-testbed-clean docker compose --progress quiet -f "$HERE/compose.yaml" exec -T host-a sh -c \
    'if [ -e /root/systemd-creds.orig ]; then mv /root/systemd-creds.orig /usr/bin/systemd-creds || exit 1; fi
     mv /root/a3.cred.orig /srv/app/a3/api_token.cred && ! dpkg -V systemd | grep -q systemd-creds &&
     systemd-creds decrypt --name=api_token /srv/app/a3/api_token.cred /dev/null >/dev/null 2>&1' </dev/null \
    || { echo "FAIL: a3 could not be restored on host-a after the $how probe"; return 1; }
}

mutate_tamper() { # mutate_tamper DIR same|keep: tamper writes a1's own value / never puts the copy back
  local f="$1/scripts/testbed/rotation.sh"
  python3 - "$f" "$2" <<'PY2'
import sys
p, how = sys.argv[1], sys.argv[2]
s = open(p).read()
a = {"same": '    print "API_TOKEN=" w; next\n',
     "keep": '  tamper_back\n  say "tamper: a1\'s saved copy is back"\n'}[how]
b = {"same": '    print "API_TOKEN=" v; next\n', "keep": '  :\n  say "tamper: a1\'s saved copy is back"\n'}[how]
if s.count(a) != 1:
    sys.exit("the tamper line is not where this check expects it")
open(p, "w").write(s.replace(a, b))
PY2
  if cmp -s "$f" "$SRC/scripts/testbed/rotation.sh"; then echo "the mutation changed nothing"; exit 1; fi
}

# tamper_red NAME WANT KEEP: the copy NAME must fail `all` on the tamper line
# WANT and still pass the line KEEP, so it is that check, not another, that fails.
tamper_red() {
  local name=$1 want=$2 keep=$3
  if run "$name" "$WORK/$name"; then
    echo "FAIL: the $name copy passed: the tamper $want check cannot fail"; return 1
  elif grep -qx "FAIL tamper: $want" "$WORK/$name.log" && grep -qx "PASS tamper: $keep" "$WORK/$name.log"; then
    echo "$name copy: the tamper check FAILS as required:"; grep '^\(PASS\|FAIL\) tamper' "$WORK/$name.log"
    jq -c '{before:[.before.carriers[]|"\(.carrier)=\(.status)"], after:[.after.carriers[]|"\(.carrier)=\(.status)"]}' "$WORK/$name-out/runs/tamper.json"
  else
    echo "FAIL: the $name copy failed, but not on the tamper $want check:"; tail -15 "$WORK/$name.log"; return 1
  fi
}

filter() { # filter NAME: the one-line jq filter rotation.sh keeps in NAME
  local f; f=$(sed -n "s/^$1='\(.*\)'\$/\1/p" "$SRC/scripts/testbed/rotation.sh")
  [ -n "$f" ] || { echo "FAIL: rotation.sh has no one-line $1" >&2; return 1; }
  printf '%s' "$f"
}

# terms NAME FILE EDIT...: the filter NAME holds on FILE from the clean run and
# fails on FILE changed by each jq EDIT, so every term of it can fail on its own.
terms() {
  local name=$1 file=$2 f e m x rc=0; shift 2
  f=$(filter "$name") || return 1
  jq -e "$f" "$file" >/dev/null || { echo "FAIL: $name does not hold on the clean run's $(basename "$file")"; return 1; }
  for e in "$@"; do
    # An edit that does not apply, or a filter that errors on its result
    # (jq exit above 1), proves nothing: only a plain false counts.
    if ! m=$(jq -c "$e" "$file") || [ -z "$m" ] || [ "$m" = "$(jq -c . "$file")" ]; then
      echo "FAIL: the edit $e does not change $(basename "$file")"; rc=1; continue
    fi
    x=0; jq -e "$f" <<<"$m" >/dev/null 2>&1 || x=$?
    case $x in
      1) ;;
      0) echo "FAIL: $name still holds after $e"; rc=1 ;;
      *) echo "FAIL: $name errors after $e instead of failing"; rc=1 ;;
    esac
  done
  [ $rc != 0 ] || echo "$name: holds on the clean run and fails on each of its $# edits"
  return $rc
}

copy "$WORK/clean"; copy "$WORK/mutant"; mutate "$WORK/mutant"
copy "$WORK/hosts"; mutate_hosts "$WORK/hosts"
copy "$WORK/credunit"; mutate_credunit "$WORK/credunit"
copy "$WORK/tsame"; mutate_tamper "$WORK/tsame" same
copy "$WORK/tkeep"; mutate_tamper "$WORK/tkeep" keep

status=0
if run clean "$WORK/clean"; then
  echo "clean copy: scenarios PASS"
else
  echo "FAIL: the unmodified copy does not pass; the red run below would prove nothing"; tail -20 "$WORK/clean.log"; status=1
fi
if [ $status -eq 0 ]; then
  if run mutant "$WORK/mutant"; then
    echo "FAIL: the mutated server passed scenario 2: the check cannot fail"; status=1
  elif grep -q '^FAIL scenario 2' "$WORK/mutant.log"; then
    echo "mutated copy: scenario 2 FAILS as required:"; grep '^\(PASS\|FAIL\) scenario 2' "$WORK/mutant.log"
  else
    echo "FAIL: the mutated run failed, but not on scenario 2:"; tail -15 "$WORK/mutant.log"; status=1
  fi
  a3='(.carriers[]|select(.path=="/srv/app/a3/api_token.cred"))'
  terms A3_KIND_OK "$WORK/clean-out/runs/01-state.json" \
    "$a3.kind = \"file\"" "del($a3)" ".carriers += [$a3]" || status=1
  terms SEALED_OK "$WORK/clean-out/receipt.json" \
    '.sealed_carriers[0].carrier = "a1"' '.sealed_carriers[0].tool_package = "busybox"' \
    '.sealed_carriers[0].tool_as_shipped = false' '.sealed_carriers[0].tool = "busybox 1.36"' \
    '.sealed_carriers[0].value_in_file = true' '.sealed_carriers[0].decrypts_under_its_name = false' \
    '.sealed_carriers[0].decrypts_under_another_name = true' '.sealed_carriers = []' \
    '.sealed_carriers += .sealed_carriers' 'del(.sealed_carriers)' || status=1
  v() { printf '(.versions[]|select(.version=="%s")|.status)' "$1"; }
  terms ROLLED_BACK "$WORK/clean-out/runs/02-meta.json" \
    "$(v 2) = \"previous\" | $(v 3) = \"current\"" "$(v 3) = \"current\"" "$(v 2) = \"disabled\"" \
    "$(v 2) = \"previous\"" "$(v 1) = \"current\"" '.versions |= map(select(.version != "3"))' || status=1
  cv() { printf '.carriers[] |= (if .carrier == "%s" then %s else . end)' "$1" "$2"; }
  terms ON_PREVIOUS "$WORK/clean-out/runs/02-carrier-versions.json" \
    "$(cv a1 '.verify = "mismatch"')" "$(cv a3 '.version = "3"')" "$(cv b2 '.holds = "new"')" \
    "$(cv a2 '.value_as_before_run = false')" 'del(.carriers[0])' '.previous_version = "1"' '.new_version = null' \
    '.current_version = "3"' '.verify_ok = false' || status=1
  tc() { printf '.%s.carriers[] |= (if .carrier == "%s" then %s else . end)' "$1" "$2" "$3"; }
  terms TAMPER_BEFORE "$WORK/clean-out/runs/tamper.json" \
    "$(tc before a1 '.status = "match"')" "$(tc before a1 '.error_class = "unhealthy"')" "$(tc before a1 '.fingerprint_match = true')" \
    "$(tc before b1 '.status = "mismatch"')" 'del(.before.carriers[1])' '.before.ok = true' '.carrier = "b1"' || status=1
  terms TAMPER_AFTER "$WORK/clean-out/runs/tamper.json" \
    "$(tc after a1 '.status = "mismatch"')" "$(tc after b2 '.fingerprint_match = false')" 'del(.after.carriers[0])' '.after.ok = false' || status=1
  if grep -qx 'PASS scenario 2: every carrier holds the previous version again (verify_carriers, fingerprint, value)' "$WORK/clean.log"; then
    echo "clean run: check_failed runs the version table check"
  else
    echo "FAIL: the clean run printed no version table check: check_failed does not run ON_PREVIOUS"; status=1
  fi
  if grep -qx 'PASS scenario 2: rolled back: the new version disabled, the old one current' "$WORK/clean.log"; then
    echo "clean run: check_failed runs the rollback check"
  else
    echo "FAIL: the clean run printed no rollback check: check_failed does not run ROLLED_BACK"; status=1
  fi
  for how in tool unbound othername plaintext; do probe_sealed "$how" || status=1; done
  if run credunit "$WORK/credunit"; then
    echo "FAIL: verify without the credential name passed scenario 1: the check cannot fail"; status=1
  elif grep -q '^FAIL scenario 1' "$WORK/credunit.log" \
    && jq -e '.ok == false and .error_class == "verify_failed"' "$WORK/credunit-out/runs/01-rotate.json" >/dev/null \
    && jq -e '[.steps[]|select(.verify == "failed")] == [.steps[]|select(.path == "/srv/app/a3/api_token.cred")]
          and ([.steps[]|select(.verify == "failed")|.error_class] == ["verify_failed"])' "$WORK/credunit-out/runs/01-state.json" >/dev/null; then
    echo "verify without the credential name: scenario 1 FAILS with verify_failed, a3 the only carrier that failed:"
    jq -c '{ok,error_class}' "$WORK/credunit-out/runs/01-rotate.json"
    jq -c '[.steps[]|{path,verify,error_class}]' "$WORK/credunit-out/runs/01-state.json"
    grep '^\(PASS\|FAIL\) scenario 1' "$WORK/credunit.log"
  else
    echo "FAIL: verify without the credential name failed, but not as verify_failed at a3:"; tail -15 "$WORK/credunit.log"
    jq -c '{ok,error_class}' "$WORK/credunit-out/runs/01-rotate.json" 2>/dev/null || true
    jq -c '[.steps[]|{path,verify,error_class}]' "$WORK/credunit-out/runs/01-state.json" 2>/dev/null || true; status=1
  fi
  for p in mutant credunit; do TESTBED_PROJECT="keep-testbed-$p" docker compose -f "$HERE/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true; done
  tamper_red tsame 'before, a1 fingerprint_mismatch and the other four match' 'after the copy is back, all five match' || status=1
  TESTBED_PROJECT=keep-testbed-tsame docker compose -f "$HERE/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true
  tamper_red tkeep 'after the copy is back, all five match' 'before, a1 fingerprint_mismatch and the other four match' || status=1
  TESTBED_PROJECT=keep-testbed-tkeep docker compose -f "$HERE/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true
  if run hosts "$WORK/hosts"; then
    echo "FAIL: two hosts sharing a machine id passed: the hosts check cannot fail"; status=1
  elif grep -q '^FAIL hosts:' "$WORK/hosts.log"; then
    echo "shared machine id: the hosts check FAILS as required:"; grep '^\(PASS\|FAIL\) hosts:' "$WORK/hosts.log"
  else
    echo "FAIL: the shared machine id run failed, but not on the hosts check:"; tail -15 "$WORK/hosts.log"; status=1
  fi
fi
exit $status
