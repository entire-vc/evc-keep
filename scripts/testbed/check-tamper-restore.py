#!/usr/bin/env python3
"""Run the real tamper command against a failed external Docker transport.

The Docker shim uses disposable local files for the remote hosts and fails the
first MCP call. No Keep functions are replaced, and no carrier value is printed.
"""
import os
from pathlib import Path
import secrets
import signal
import subprocess
import tempfile


SCRIPT = Path(__file__).with_name("rotation.sh")
# mock: external boundary — Docker transport and disposable remote host files.
DOCKER = r'''#!/usr/bin/env python3
import os
from pathlib import Path
import subprocess
import sys

root = Path(os.environ["TAMPER_PROBE_ROOT"])
args = sys.argv[sys.argv.index("exec") + 1:]
child_env = os.environ.copy()
while args[0].startswith("-"):
    option = args.pop(0)
    if option == "-e":
        key, value = args.pop(0).split("=", 1)
        child_env[key] = value
host = args.pop(0)
if host == "agent":
    sys.stdin.read()
    original = (root / "original").read_bytes()
    assert (root / "host-a/srv/app/a1/app.env").read_bytes() != original
    (root / "mcp-reached").touch()
    if os.environ["TAMPER_PROBE_FAILURE"] == "transport":
        sys.exit(42)
    print('{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"probe failure"}}')
    sys.exit(0)

def mapped(text):
    for prefix in ("/srv/app/", "/root/", "/operator/"):
        text = text.replace(prefix, str(root / host) + prefix)
    return text

args = [mapped(arg) for arg in args]
if "F" in child_env:
    child_env["F"] = mapped(child_env["F"])
stdin = None
if args[:2] == ["sh", "-s"]:
    # The host is Linux; the probe can also run on macOS. Ownership changes
    # are external host operations and irrelevant to the restore assertion.
    stdin = ("chown() { :; }; chmod() { :; };\n" + sys.stdin.read()).encode()
sys.exit(subprocess.run(args, input=stdin, env=child_env).returncode)
'''


def probe(failure):
    with tempfile.TemporaryDirectory(prefix="testbed-tamper-restore-") as work:
        root = Path(work)
        for directory in ("bin", "host-a/srv/app/a1", "host-a/root",
                          "operator/operator/needles", "out/state", "out/runs", "out/mcp"):
            (root / directory).mkdir(parents=True)
        (root / "out/.keep-testbed-out").touch()
        (root / "out/state/org").write_text("probe-org")
        original = ("API_TOKEN=" + secrets.token_hex(32) + "\n").encode()
        (root / "original").write_bytes(original)
        carrier = root / "host-a/srv/app/a1/app.env"
        carrier.write_bytes(original)
        docker = root / "bin/docker"
        docker.write_text(DOCKER)
        docker.chmod(0o700)
        child_env = dict(os.environ, PATH=str(root / "bin") + os.pathsep + os.environ["PATH"],
                         TESTBED_OUT=str(root / "out"), TAMPER_PROBE_ROOT=str(root),
                         TAMPER_PROBE_FAILURE=failure)
        with (root / "stdout").open("wb") as stdout, (root / "stderr").open("wb") as stderr:
            process = subprocess.Popen(["bash", str(SCRIPT), "tamper"], env=child_env,
                                       stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                       start_new_session=True)
            timed_out = False
            try:
                returncode = process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                timed_out = True
            finally:
                # Also reap transport children if the command failed or timed out.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
        output = (root / "stdout").read_bytes() + (root / "stderr").read_bytes()
        # Never print captured output: it is itself part of the leak assertion.
        assert (root / "mcp-reached").exists(), "MCP failure was not reached after changing a1"
        assert carrier.read_bytes() == original, "a1 was not restored after MCP failure"
        assert not timed_out, "tamper did not exit after MCP failure"
        assert returncode != 0, "MCP failure was reported as success"
        assert not (root / "host-a/root/a1-app.env.tamper").exists(), "saved copy remains"
        for needle in (root / "operator/operator/needles").iterdir():
            value = needle.read_bytes()
            assert value and value not in output, "carrier value leaked"
        assert original.split(b"=", 1)[1].strip() not in output, "original leaked"
        print("PASS tamper restores a1 after MCP " + failure + " failure; no value in output")


for kind in ("transport", "error-reply"):
    probe(kind)
