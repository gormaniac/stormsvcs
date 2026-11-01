"""Pytests for pcapsvc.sandbox and pcapsvc._sbxexec, the sandbox engines run in."""


import os
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
            assert res.code != 0 and b"PermissionError" in res.stderr, family
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
            assert res.code != 0 and b"PermissionError" in res.stderr, code

    async def test_limits(self, run):
        probe, _ = run
        # A busy loop is killed by the CPU limit (1 second), well before the timeout.
        res = await probe("while True: pass", timeout=30)
        assert res.code != 0
        # Endless output is killed by the output cap.
        with pytest.raises(p_sandbox.SandboxError, match="wrote more than"):
            await probe("import sys\nwhile True: sys.stdout.write('x' * 65536)", maxoutput=1 << 20)
