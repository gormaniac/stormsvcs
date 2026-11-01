"""Pytests for pcapsvc.sandbox and pcapsvc._sbxexec, the sandbox engines run in."""


import os
import signal
import sys

import pytest

from pcapsvc import _sbxexec
from pcapsvc import sandbox as p_sandbox

LANDLOCK = _sbxexec.landlockAbi()
needsLandlock = pytest.mark.skipif(not LANDLOCK, reason="the kernel doesn't support Landlock")
needsLandlockTcp = pytest.mark.skipif(LANDLOCK < 4, reason="Landlock can't restrict TCP here")


@pytest.fixture
def dirs(tmp_path):
    allowed = tmp_path / "allowed"
    out = tmp_path / "out"
    allowed.mkdir()
    out.mkdir()
    (allowed / "a.txt").write_text("ok")
    (tmp_path / "secret.txt").write_text("secret")
    return tmp_path


async def runPy(sbx, code, dirs, **kwargs):
    py = os.path.realpath(sys.executable)
    # Hands the directories to the engine's user, when it runs as one (as root).
    sbx.prepare(str(dirs / "allowed"), str(dirs / "out"))
    return await sbx.run([py, "-I", "-S", "-c", code], read=[str(dirs / "allowed")],
                         write=[str(dirs / "out")], execs=[sys.prefix, sys.base_prefix],
                         **kwargs)


class TestSandbox:

    async def test_allowed(self, dirs):
        sbx = p_sandbox.Sandbox()
        res = await runPy(sbx, f"print(open({str(dirs / 'allowed/a.txt')!r}).read())", dirs)
        assert res.code == 0 and res.stdout.strip() == b"ok"
        res = await runPy(sbx, f"open({str(dirs / 'out/x')!r}, 'w').write('y')", dirs)
        assert res.code == 0
        assert (dirs / "out/x").read_text() == "y"

    @needsLandlock
    async def test_landlock(self, dirs):
        sbx = p_sandbox.Sandbox()
        res = await runPy(sbx, f"open({str(dirs / 'secret.txt')!r}).read()", dirs)
        assert res.code != 0 and b"PermissionError" in res.stderr
        res = await runPy(sbx, f"open({str(dirs / 'allowed/x')!r}, 'w')", dirs)
        assert res.code != 0 and b"PermissionError" in res.stderr
        assert not (dirs / "allowed/x").exists()

        # Off doesn't restrict anything.
        res = await runPy(p_sandbox.Sandbox(mode="off"),
                          f"print(open({str(dirs / 'secret.txt')!r}).read())", dirs)
        assert res.stdout.strip() == b"secret"

    async def test_seccomp(self, dirs):
        sbx = p_sandbox.Sandbox()
        for family in ("AF_INET", "AF_INET6"):
            res = await runPy(sbx, f"import socket; socket.socket(socket.{family}, "
                                   "socket.SOCK_DGRAM)", dirs)
            # Killed (SIGSYS), and reported: the engines never open network sockets.
            assert res.code == -signal.SIGSYS, family
            assert [a["kind"] for a in res.alerts] == ["seccomp"], family
        res = await runPy(sbx, "import socket; socket.socket(socket.AF_UNIX); print('ok')", dirs)
        assert res.stdout.strip() == b"ok"

        # Without seccomp, Landlock still blocks TCP connects (ABI 4+), UDP is allowed.
        nosec = p_sandbox.Sandbox(seccomp=False)
        res = await runPy(nosec, "import socket; socket.socket(socket.AF_INET, "
                                 "socket.SOCK_DGRAM); print('ok')", dirs)
        assert res.stdout.strip() == b"ok"

    @needsLandlockTcp
    async def test_tcp(self, dirs):
        sbx = p_sandbox.Sandbox(seccomp=False)
        code = ("import socket; s = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen(); "
                "print('listening')")
        res = await runPy(sbx, code, dirs)
        assert res.code != 0 and b"PermissionError" in res.stderr

    async def test_env_rlimits(self, dirs):
        sbx = p_sandbox.Sandbox(rlimits={"nofile": 77})
        # Python itself adds LC_CTYPE (PEP 538), nothing else comes from the service.
        code = ("import os, resource; print(sorted(set(os.environ) - {'LC_CTYPE'}), "
                "resource.getrlimit(resource.RLIMIT_NOFILE))")
        res = await runPy(sbx, code, dirs, env={"PATH": "/usr/bin:/bin", "ONLY": "this"})
        assert res.stdout.strip() == b"['ONLY', 'PATH'] (77, 77)"

        res = await runPy(sbx, "import resource; print(resource.getrlimit(resource.RLIMIT_CORE))",
                          dirs)
        assert res.stdout.strip() == b"(0, 0)"

    async def test_bounds(self, dirs):
        sbx = p_sandbox.Sandbox()
        with pytest.raises(p_sandbox.SandboxError, match="took longer than 0.5 seconds"):
            await runPy(sbx, "import time; time.sleep(30)", dirs, timeout=0.5)
        with pytest.raises(p_sandbox.SandboxError, match="wrote more than 100 bytes"):
            await runPy(sbx, "print('x' * 100000)", dirs, maxoutput=100)

        # The whole process group is killed, not only the engine.
        code = ("import subprocess, sys, time; subprocess.Popen([sys.executable, '-c', "
                "'import time; time.sleep(60)']); print('started', flush=True); time.sleep(60)")
        with pytest.raises(p_sandbox.SandboxError):
            await runPy(p_sandbox.Sandbox(mode="off"), code, dirs, timeout=1)

        # stdout to a file.
        res = await runPy(sbx, "print('to a file')", dirs, stdout=str(dirs / "out/stdout.txt"))
        assert res.stdout == b""
        assert (dirs / "out/stdout.txt").read_text() == "to a file\n"

    async def test_errors(self, dirs):
        sbx = p_sandbox.Sandbox()
        with pytest.raises(p_sandbox.SandboxError, match="Unable to find"):
            await sbx.run(["/nonexistent/engine"])

        # A layer that can't be applied fails a strict run, and is a warning otherwise.
        strict = p_sandbox.Sandbox(mode="strict", rlimits={"nofile": "lots"})
        with pytest.raises(p_sandbox.SandboxError, match="rlimits"):
            await runPy(strict, "print('ran')", dirs)
        loose = p_sandbox.Sandbox(rlimits={"nofile": "lots"})
        res = await runPy(loose, "print('ran')", dirs)
        assert res.stdout.strip() == b"ran"
        assert any("rlimits skipped" in w for w in res.warnings)

        with pytest.raises(p_sandbox.SandboxError, match="Invalid sandbox mode"):
            p_sandbox.Sandbox(mode="nope")

    def test_probe(self):
        probe = p_sandbox.Sandbox().probe()
        assert probe["mode"] == "best-effort"
        assert probe["landlock"] == LANDLOCK
        assert probe["landlock:tcp"] == (LANDLOCK >= 4)
        assert ("landlock" in probe["missing"]) == (not LANDLOCK)

    def test_spec(self):
        spec = p_sandbox.Sandbox(mode="strict").spec(["/x"], ["/y"], ["/z"], {"A": "b"}, "/y")
        assert spec["strict"] and spec["landlock"] and spec["seccomp"]
        assert "/x" in spec["read"] and "/etc/ld.so.cache" in spec["read"]
        assert "/etc" not in spec["read"] and "/etc/shadow" not in spec["read"]
        assert "/y" in spec["write"] and "/dev/null" in spec["write"]
        assert "/z" in spec["exec"] and "/usr" in spec["exec"]
        assert spec["env"] == {"A": "b"} and spec["cwd"] == "/y"

    def test_exec_usage(self):
        # Bad invocations exit with the sandbox's exit code.
        import subprocess
        res = subprocess.run([sys.executable, "-I", _sbxexec.__file__, "{}"],
                             capture_output=True)
        assert res.returncode == _sbxexec.EXIT_SANDBOX and b"usage" in res.stderr
        res = subprocess.run([sys.executable, "-I", _sbxexec.__file__, "not json", "--", "true"],
                             capture_output=True)
        assert res.returncode == _sbxexec.EXIT_SANDBOX and b"invalid spec" in res.stderr
        res = subprocess.run([sys.executable, "-I", _sbxexec.__file__, "{}", "--",
                              "/nonexistent/x"], capture_output=True)
        assert res.returncode == _sbxexec.EXIT_SANDBOX and b"unable to run" in res.stderr


@needsLandlock
class TestProbes:
    """What a compromised engine tries, through the same wrapper the engines run in."""

    @pytest.fixture
    def run(self, tmp_path):
        # The run's input (read only), its output dir, and another run's capture next to it.
        work = tmp_path / "run"
        out = work / "out"
        out.mkdir(parents=True)
        capture = work / "capture.pcap"
        capture.write_bytes(b"pcap")
        other = tmp_path / "other"
        other.mkdir()
        (other / "capture.pcap").write_bytes(b"someone else's capture")
        sbx = p_sandbox.Sandbox(rlimits={"cpu": 1})

        async def probe(code, **kwargs):
            py = os.path.realpath(sys.executable)
            sbx.prepare(str(work))
            return await sbx.run(
                [py, "-I", "-S", "-c", code],
                read=[str(capture)],
                write=[str(out)],
                execs=[sys.prefix, sys.base_prefix],
                **kwargs,
            )

        return probe, tmp_path

    async def test_reads(self, run):
        probe, tmp = run
        for path in ("/etc/shadow", "/proc/1/environ", str(tmp / "other/capture.pcap"),
                     "/root/.bashrc", "/vertex/storage/cell.yaml", str(tmp)):
            res = await probe(f"import os; print(open({path!r}).read() if os.path.isfile({path!r}) "
                              f"else os.listdir({path!r}))")
            assert res.code != 0, (path, res.stdout)
            assert b"PermissionError" in res.stderr or b"FileNotFoundError" in res.stderr, path
        # Its own input is readable.
        res = await probe(f"print(open({str(tmp / 'run/capture.pcap')!r}).read())")
        assert res.stdout.strip() == b"pcap"

    async def test_writes(self, run):
        probe, tmp = run
        for path in ("/tmp/x", str(tmp / "run/capture.pcap"), str(tmp / "other/x"),
                     "/dev/shm/x"):
            res = await probe(f"open({path!r}, 'w').write('x')")
            assert res.code != 0 and b"PermissionError" in res.stderr, path
        assert (tmp / "run/capture.pcap").read_bytes() == b"pcap"
        res = await probe(f"open({str(tmp / 'run/out/x')!r}, 'w').write('x')")
        assert res.code == 0

    async def test_network(self, run):
        probe, _ = run
        for code in (
            "import socket; socket.create_connection(('127.0.0.1', 1), timeout=1)",
            "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
            "s.sendto(b'x', ('127.0.0.1', 9))",
            "import socket; socket.socket(socket.AF_INET6, socket.SOCK_STREAM)",
            "import socket; socket.socket(socket.AF_PACKET, socket.SOCK_RAW)",
        ):
            res = await probe(code)
            assert res.code == -signal.SIGSYS, code
            assert res.alerts and res.alerts[0]["kind"] == "seccomp", code

    async def test_limits(self, run):
        probe, _ = run
        # A busy loop is killed by the CPU limit (1 second), well before the timeout.
        res = await probe("while True: pass", timeout=30)
        assert res.code != 0
        # Endless output is killed by the output cap.
        with pytest.raises(p_sandbox.SandboxError, match="wrote more than"):
            await probe("import sys\nwhile True: sys.stdout.write('x' * 65536)", maxoutput=1 << 20)


class TestDetection:
    """What the sandbox reports when an engine does what it shouldn't (see ALERT_KINDS)."""

    async def test_verified(self, dirs):
        # The engine's /proc status is checked against the layers its wrapper applied.
        sbx = p_sandbox.Sandbox()
        res = await runPy(sbx, "import time; time.sleep(0.3); print('ok')", dirs)
        assert res.stdout.strip() == b"ok" and res.alerts == []
        assert "no_new_privs" in res.applied and res.verified is True

    def test_check_status(self):
        status = {"Uid": "2000\t2000\t2000\t2000", "Gid": "2000\t2000\t2000\t2000",
                  "Groups": "", "NoNewPrivs": "1", "Seccomp": "2", "CapEff": "0000000000000000"}
        layers = ["rlimits", "user", "no_new_privs", "landlock", "seccomp"]
        check = p_sandbox.checkStatus
        assert check(status, layers, (2000, 2000), True) == []
        bad = {**status, "Uid": "2000\t0\t2000\t2000", "NoNewPrivs": "0", "Seccomp": "0",
               "Groups": "0", "CapEff": "000001ffffffffff"}
        problems = check(bad, layers, (2000, 2000), True)
        assert len(problems) == 5
        assert any("uids 2000 0" in p for p in problems)
        # Layers the wrapper reported skipped (best-effort) aren't expected.
        assert check({**status, "Seccomp": "0"}, ["user", "no_new_privs"], (2000, 2000), True) == []

    async def test_crash(self, dirs):
        sbx = p_sandbox.Sandbox()
        res = await runPy(sbx, "import os; os.abort()", dirs)
        assert res.code == -signal.SIGABRT
        assert [a["kind"] for a in res.alerts] == ["crash"]
        assert "SIGABRT" in res.alerts[0]["detail"]
        res = await runPy(sbx, "import ctypes; ctypes.string_at(0)", dirs)
        assert [a["kind"] for a in res.alerts] == ["crash"] and "SIGSEGV" in res.alerts[0]["detail"]
        # Exiting with an error isn't a crash.
        res = await runPy(sbx, "raise SystemExit(3)", dirs)
        assert res.code == 3 and res.alerts == []

    async def test_leftover(self, dirs):
        # A child the engine leaves running in its process group is killed and reported.
        sbx2 = p_sandbox.Sandbox()
        code = ("import subprocess, sys; subprocess.Popen([sys.executable, '-c', "
                "'import time; time.sleep(60)']); print('left one')")
        res = await runPy(sbx2, code, dirs)
        assert res.stdout.strip() == b"left one"
        assert [a["kind"] for a in res.alerts] == ["leftover"]

    async def test_escaped(self, dirs):
        # A child that leaves the run's process group (setsid) and is orphaned to the service
        # (the sandbox makes it a child subreaper) is found by the sweep, killed, and reported.
        sbx = p_sandbox.Sandbox()
        if not sbx.subreaper:
            pytest.skip("can't be a child subreaper here")
        code = ("import os, time\n"
                "if os.fork() == 0:\n"
                "    os.setsid()\n"
                "    time.sleep(60)\n"
                "    os._exit(0)\n"
                "print('escaped')")
        res = await runPy(sbx, code, dirs)
        assert res.stdout.strip() == b"escaped"
        assert [a["kind"] for a in res.alerts] == ["escaped"]
        assert "orphaned to the service" in res.alerts[0]["detail"] or \
            "left its run's process group" in res.alerts[0]["detail"]
        pid = int(res.alerts[0]["detail"].split()[1])
        assert not os.path.exists(f"/proc/{pid}") or \
            "Z" in open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[0]

    def test_sandboxed_marker(self):
        own = {"Seccomp_filters": "1", "NoNewPrivs": "0"}
        assert p_sandbox.sandboxed({"Seccomp_filters": "2", "NoNewPrivs": "0"}, own)
        assert p_sandbox.sandboxed({"Seccomp_filters": "1", "NoNewPrivs": "1"}, own)
        # The service's other children (ex. Synapse's IO workers) aren't.
        assert not p_sandbox.sandboxed({"Seccomp_filters": "1", "NoNewPrivs": "0"}, own)
        assert not p_sandbox.sandboxed({"Seccomp_filters": "1", "NoNewPrivs": "1"},
                                       {"Seccomp_filters": "1", "NoNewPrivs": "1"})

    async def test_sweep_spares_others(self, dirs):
        # A child of the service that wasn't started in the sandbox isn't touched.
        import subprocess

        sbx = p_sandbox.Sandbox()
        other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            res = await runPy(sbx, "print('ok')", dirs)
            assert res.alerts == [] and other.poll() is None
            assert sbx.sweep() == []
        finally:
            other.kill()
            other.wait()

    async def test_run_alerts(self, dirs):
        # An analysis collects the alerts of every engine run in its context.
        sbx = p_sandbox.Sandbox()
        token = p_sandbox.RUN_ALERTS.set([])
        try:
            await runPy(sbx, "import os; os.abort()", dirs)
            alerts = p_sandbox.RUN_ALERTS.get()
        finally:
            p_sandbox.RUN_ALERTS.reset(token)
        assert [a["kind"] for a in alerts] == ["crash"]
        assert sbx.alertcount == 1 and list(sbx.alerts) == alerts

    def test_sweep_files(self, tmp_path):
        sbx = p_sandbox.Sandbox()
        if sbx.ids() is None:
            pytest.skip("needs the sandbox user (the tests running as root, in the test image)")
        uid, gid = sbx.ids()
        work = tmp_path / "work"
        work.mkdir()
        (work / "fine").write_text("x")
        os.chown(work / "fine", uid, gid)
        planted = tmp_path / "planted"
        planted.write_text("x")
        os.chown(planted, uid, gid)
        (tmp_path / "root-owned").write_text("x")
        assert sbx.sweepFiles([str(tmp_path)], exclude=[str(work)]) == [str(planted)]
        assert sbx.alerts[-1]["kind"] == "file"



def test_landlock_log_flag(monkeypatch):
    # On Landlock ABI 7, the engine's denials are logged to the audit log (they're after an
    # exec, which isn't logged by default).
    calls = []

    class FakeLibc:
        class syscall:  # noqa: N801 - mimics ctypes' function object
            restype = None

            def __new__(cls, nr, *args):
                calls.append((nr, args))
                if nr == _sbxexec.SYS_LANDLOCK_CREATE_RULESET:
                    return 7 if args[0] is None else 99
                return 0

    monkeypatch.setattr(os, "close", lambda fd: None)
    _sbxexec.applyLandlock([], [], [], FakeLibc)
    restrict = [args for nr, args in calls if nr == _sbxexec.SYS_LANDLOCK_RESTRICT_SELF]
    assert restrict[0][1].value == _sbxexec.LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON
