#!/usr/bin/env python3
"""Anonymous oversized POSTs must not kill the Vault process this manifest runs.

vault.yaml starts the official vault image, generates a TCP listener, and caps
the container at resources.limits.memory. These tests download that image's
Vault release, start it with the generated listener under that memory limit,
and POST one large JSON body with no token.

The suite fails while that request makes the kernel OOM-kill the process.
It passes once the crash is no longer reachable from the internet: the
listener's max request size keeps the read under the memory limit, the memory
limit is large enough that this request cannot exhaust it, or the Service no
longer accepts connections from the open internet.

The same listener limit is applied before the body is parsed for every POST.
This file starts a fresh process for the unauthenticated unseal and init
routes and for two routes that parse the body before checking a token
(/v1/sys/seal and an arbitrary logical path). Other POST routes that share
that parser are not started on their own process: /v1/sys/step-down,
/v1/sys/rekey/init, /v1/sys/rekey/update, /v1/sys/rekey/verify,
/v1/sys/generate-root/attempt, /v1/sys/generate-root/update, and the remaining
/v1/* logical paths.

Run:
  python3 -m unittest tests.vault_request_memory_test -v
"""

import hashlib
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import unittest
import urllib.request

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MANIFEST = os.path.join(REPO_ROOT, "vault.yaml")
WORKDIR = "/tmp/vault-request-memory-test"
CGROUP = "/sys/fs/cgroup/vaultreqmemtest"
# About a hundred mebibytes, the size named by the report.
ATTACK_BODY_BYTES = 100 * 1024 * 1024
RELEASE_BASE = "https://releases.hashicorp.com/vault"


def _documents(text):
    parts = re.split(r"^---\s*$", text, flags=re.M)
    return [part for part in parts if part.strip()]


def _block_after(text, start, stop_indent):
    """Return lines after `start` until a line with indent <= stop_indent."""
    lines = text[start:].splitlines()
    if not lines:
        return ""
    first = lines[0]
    out = [first]
    for line in lines[1:]:
        if line.strip() == "":
            out.append(line)
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= stop_indent:
            break
        out.append(line)
    return "\n".join(out)


def parse_quantity(value):
    """Parse a Kubernetes memory quantity into bytes."""
    value = value.strip().strip('"').strip("'")
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([eEinumkKMGTP]i?)?", value)
    if not match:
        raise ValueError("unsupported memory quantity %r" % value)
    number = float(match.group(1))
    suffix = match.group(2) or ""
    binary = {
        "Ki": 1024,
        "Mi": 1024 ** 2,
        "Gi": 1024 ** 3,
        "Ti": 1024 ** 4,
        "Pi": 1024 ** 5,
        "Ei": 1024 ** 6,
    }
    decimal = {
        "n": 1e-9,
        "u": 1e-6,
        "m": 1e-3,
        "k": 1e3,
        "K": 1e3,
        "M": 1e6,
        "G": 1e9,
        "T": 1e12,
        "P": 1e15,
        "E": 1e18,
    }
    if suffix in binary:
        scale = binary[suffix]
    elif suffix in decimal:
        scale = decimal[suffix]
    elif suffix == "":
        scale = 1
    else:
        raise ValueError("unsupported memory quantity %r" % value)
    return int(number * scale)


def parse_manifest(text):
    docs = _documents(text)
    service = None
    workload = None
    for doc in docs:
        kind = re.search(r"^kind:\s*(\S+)", doc, re.M)
        if not kind:
            continue
        if kind.group(1) == "Service":
            service = doc
        elif kind.group(1) in ("StatefulSet", "Deployment", "DaemonSet"):
            workload = doc
    if service is None or workload is None:
        raise AssertionError("vault.yaml is missing a Service or workload")

    type_match = re.search(r"^\s*type:\s*(\S+)", service, re.M)
    service_type = type_match.group(1) if type_match else "ClusterIP"
    ranges = []
    range_match = re.search(r"^\s*loadBalancerSourceRanges:\s*(.*)$", service, re.M)
    if range_match:
        rest = range_match.group(1).strip()
        if rest in ("", "[]", "null", "~"):
            ranges = []
        elif rest.startswith("["):
            ranges = re.findall(r"[0-9a-fA-F:.]+/\d+", rest)
        else:
            # Following list items.
            lines = service[range_match.end():].splitlines()
            for line in lines:
                item = re.match(r"^\s*-\s*(\S+)", line)
                if item:
                    ranges.append(item.group(1).strip("\"'"))
                    continue
                if line.strip() == "":
                    continue
                break

    container = re.search(r"-\s*name:\s*vault\s*\n\s*image:\s*['\"]?([^'\"\s]+)", workload)
    if not container:
        raise AssertionError("vault container image not found")
    image = container.group(1)
    section = _block_after(workload, container.start(), 8)
    mem_match = re.search(r"^\s*memory:\s*['\"]?([^'\"\s]+)", section, re.M)
    if not mem_match:
        raise AssertionError("vault container memory limit not found")
    memory_limit = parse_quantity(mem_match.group(1))

    heredoc = re.search(
        r"cat > /etc/vault/config/vault\.hcl <<EOF\n(.*?)\n[ \t]*EOF",
        workload,
        re.S,
    )
    if not heredoc:
        raise AssertionError("generated vault.hcl heredoc not found")
    # The heredoc is indented with the shell script. Strip that common indent
    # and keep the listener text, including any max_request_size added later.
    hcl_lines = heredoc.group(1).splitlines()
    dedented = []
    indents = [len(line) - len(line.lstrip(" ")) for line in hcl_lines if line.strip()]
    trim = min(indents) if indents else 0
    for line in hcl_lines:
        if line.strip() == "":
            dedented.append("")
        else:
            dedented.append(line[trim:])
    hcl = "\n".join(dedented) + "\n"

    return {
        "service_type": service_type,
        "source_ranges": ranges,
        "image": image,
        "memory_limit": memory_limit,
        "hcl": hcl,
    }


def _world_range(cidr):
    return cidr in ("0.0.0.0/0", "::/0")


def internet_exposed(parsed):
    """True when a client anywhere on the internet can open the published port."""
    if parsed["service_type"] not in ("LoadBalancer", "NodePort"):
        return False
    ranges = parsed["source_ranges"]
    if not ranges:
        return True
    return any(_world_range(item) for item in ranges)


def image_version(image):
    ref = image.split("@", 1)[0]
    if ":" not in ref:
        raise AssertionError("vault image %r has no release tag" % image)
    tag = ref.rsplit(":", 1)[1]
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?", tag):
        raise AssertionError("vault image tag %r is not a HashiCorp release version" % tag)
    return tag


def listener_address(hcl):
    match = re.search(r'address\s*=\s*"([^"]+)"', hcl)
    if not match:
        raise AssertionError("listener address not found in generated config")
    host, port = match.group(1).rsplit(":", 1)
    return host, int(port)


def prepare_hcl(hcl, cert_path, key_path, data_dir):
    """Keep the generated listener. Swap only paths the local process needs."""
    text = hcl.replace("/etc/vault/tls/vault.crt", cert_path).replace(
        "/etc/vault/tls/vault.key", key_path
    )
    text = _replace_gcs_storage(text, data_dir)
    if 'storage "' not in text:
        text += '\nstorage "file" {\n  path = "%s"\n}\n' % data_dir
    return text


def _replace_gcs_storage(text, data_dir):
    token = 'storage "gcs"'
    start = text.find(token)
    if start < 0:
        return text
    brace = text.find("{", start)
    if brace < 0:
        raise AssertionError("gcs storage block has no opening brace")
    depth = 0
    end = None
    for index in range(brace, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                end = index + 1
                break
    if end is None:
        raise AssertionError("gcs storage block is not closed")
    replacement = 'storage "file" {\n  path = "%s"\n}' % data_dir
    return text[:start] + replacement + text[end:]


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ensure_vault_binary(version):
    os.makedirs(WORKDIR, exist_ok=True)
    zip_name = "vault_%s_linux_amd64.zip" % version
    zip_path = os.path.join(WORKDIR, zip_name)
    binary = os.path.join(WORKDIR, "vaultreqmem-%s" % version)
    sums_url = "%s/%s/vault_%s_SHA256SUMS" % (RELEASE_BASE, version, version)
    zip_url = "%s/%s/%s" % (RELEASE_BASE, version, zip_name)
    with urllib.request.urlopen(sums_url, timeout=60) as response:
        sums = response.read().decode()
    expected = None
    for line in sums.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] == zip_name:
            expected = parts[0]
            break
    if not expected:
        raise AssertionError("published checksums have no %s" % zip_name)
    if not os.path.exists(zip_path) or _sha256_file(zip_path) != expected:
        with urllib.request.urlopen(zip_url, timeout=120) as response, open(zip_path, "wb") as handle:
            shutil.copyfileobj(response, handle)
    actual = _sha256_file(zip_path)
    if actual != expected:
        raise AssertionError("vault %s checksum %s != published %s" % (version, actual, expected))
    if not os.path.exists(binary):
        subprocess.check_call(["unzip", "-o", zip_path, "-d", os.path.join(WORKDIR, "extract-%s" % version)])
        extracted = os.path.join(WORKDIR, "extract-%s" % version, "vault")
        shutil.copy2(extracted, binary)
        os.chmod(binary, 0o755)
    return binary


def _cgroup_events():
    events = {}
    with open(os.path.join(CGROUP, "memory.events")) as handle:
        for line in handle:
            key, value = line.split()
            events[key] = int(value)
    return events


def _memory_current():
    with open(os.path.join(CGROUP, "memory.current")) as handle:
        return int(handle.read().strip())


def _memory_max():
    with open(os.path.join(CGROUP, "memory.max")) as handle:
        return int(handle.read().strip())


def _rss(pid):
    with open("/proc/%s/status" % pid) as handle:
        for line in handle:
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    return 0


def _ensure_cgroup(limit):
    subprocess.check_call(["sudo", "-n", "mkdir", "-p", CGROUP])
    # The memory controller has to be delegated from the root cgroup before a
    # child can enforce memory.max.
    controllers = open("/sys/fs/cgroup/cgroup.controllers").read().split()
    if "memory" not in controllers:
        raise AssertionError("cgroup v2 memory controller is not available")
    subtree = open("/sys/fs/cgroup/cgroup.subtree_control").read().split()
    if "memory" not in subtree:
        subprocess.check_call(
            ["sudo", "-n", "sh", "-c", "echo +memory > /sys/fs/cgroup/cgroup.subtree_control"]
        )
    subprocess.check_call(["sudo", "-n", "sh", "-c", "echo %d > %s/memory.max" % (limit, CGROUP)])
    swap = os.path.join(CGROUP, "memory.swap.max")
    if os.path.exists(swap):
        subprocess.check_call(["sudo", "-n", "sh", "-c", "echo 0 > %s" % swap])
    if _memory_max() != limit:
        raise AssertionError("cgroup memory.max is %s, manifest limit is %s" % (_memory_max(), limit))


def _find_pid(binary):
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            command = open("/proc/%s/cmdline" % pid, "rb").read().replace(b"\x00", b" ").decode()
        except OSError:
            continue
        if command.startswith(binary + " "):
            return int(pid)
    return None


def _start_server(binary, config_path, limit):
    _ensure_cgroup(limit)
    log_path = os.path.join(WORKDIR, "vault.log")
    log = open(log_path, "w")
    # The executable is a normal file. Write it back, drop the page cache, and
    # fault it from inside the memory cgroup so those pages count against the
    # manifest limit the way a container's rootfs does. Unlimited memlock
    # matches the IPC_LOCK capability this manifest adds; Vault then locks
    # those pages, so the kernel cannot reclaim them to satisfy the request.
    proc = subprocess.Popen(
        [
            "sudo",
            "-n",
            "sh",
            "-c",
            "set -e; "
            "sync; "
            "echo 3 > /proc/sys/vm/drop_caches; "
            "echo $$ > %s/cgroup.procs; "
            "dd if=%s of=/dev/null bs=1M status=none; "
            "exec prlimit --memlock=unlimited -- %s server -config=%s"
            % (CGROUP, binary, binary, config_path),
        ],
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    pid = None
    for _ in range(200):
        pid = _find_pid(binary)
        if pid:
            break
        if proc.poll() is not None:
            break
        time.sleep(0.05)
    if not pid:
        log.close()
        raise AssertionError("vault did not start:\n%s" % open(log_path).read()[-2000:])
    return proc, pid, log_path


def _wait_until_listening(pid, port, timeout=20):
    deadline = time.time() + timeout
    context = ssl._create_unverified_context()
    while time.time() < deadline:
        if not os.path.exists("/proc/%s" % pid):
            return False
        try:
            raw = socket.create_connection(("127.0.0.1", port), 2)
            tls = context.wrap_socket(raw, server_hostname="localhost")
            tls.sendall(
                b"GET /v1/sys/seal-status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            )
            data = b""
            while True:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                data += chunk
            tls.close()
            if data.startswith(b"HTTP/1.1"):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _post_json(port, path, size):
    prefix = b'{"key":"'
    suffix = b'"}'
    if size < len(prefix) + len(suffix):
        raise AssertionError("body size %s is too small" % size)
    filler = size - len(prefix) - len(suffix)
    context = ssl._create_unverified_context()
    raw = socket.create_connection(("127.0.0.1", port), 10)
    tls = context.wrap_socket(raw, server_hostname="localhost")
    header = (
        "POST %s HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n" % (path, size)
    )
    tls.sendall(header.encode())
    sent = 0
    send_error = None
    try:
        tls.sendall(prefix)
        sent += len(prefix)
        block = b"A" * 65536
        left = filler
        while left:
            piece = block[: min(left, len(block))]
            tls.sendall(piece)
            sent += len(piece)
            left -= len(piece)
        tls.sendall(suffix)
        sent += len(suffix)
    except OSError as exc:
        send_error = "%s after %d bytes" % (type(exc).__name__, sent)
    data = b""
    recv_error = None
    try:
        tls.settimeout(5)
        while len(data) < 8192:
            chunk = tls.recv(4096)
            if not chunk:
                break
            data += chunk
    except OSError as exc:
        recv_error = type(exc).__name__
    try:
        tls.close()
    except OSError:
        pass
    status = data.split(b"\r\n", 1)[0].decode(errors="replace") if data else ""
    body = data.split(b"\r\n\r\n", 1)[-1][:300].decode(errors="replace") if data else ""
    return status, body, send_error, recv_error


def _stop(proc, pid):
    if pid and os.path.exists("/proc/%s" % pid):
        subprocess.call(["sudo", "-n", "kill", "-9", str(pid)])
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        subprocess.call(["sudo", "-n", "kill", "-9", str(proc.pid)])


class VaultRequestMemoryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(MANIFEST) as handle:
            cls.parsed = parse_manifest(handle.read())
        cls.version = image_version(cls.parsed["image"])
        cls.binary = ensure_vault_binary(cls.version)
        cls.host, cls.port = listener_address(cls.parsed["hcl"])

    def setUp(self):
        self._procs = []

    def tearDown(self):
        for proc, pid in self._procs:
            _stop(proc, pid)

    def _run_server(self):
        work = tempfile.mkdtemp(prefix="vault-case-", dir=WORKDIR)
        cert = os.path.join(work, "vault.crt")
        key = os.path.join(work, "vault.key")
        data = os.path.join(work, "data")
        os.makedirs(data)
        subprocess.check_call(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key,
                "-out",
                cert,
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=localhost",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        config = os.path.join(work, "vault.hcl")
        with open(config, "w") as handle:
            handle.write(prepare_hcl(self.parsed["hcl"], cert, key, data))
        proc, pid, log_path = _start_server(self.binary, config, self.parsed["memory_limit"])
        self._procs.append((proc, pid))
        return proc, pid, log_path

    def _assert_accounted(self, pid):
        cgroup = open("/proc/%s/cgroup" % pid).read()
        self.assertIn("vaultreqmemtest", cgroup, "vault is not in the memory cgroup")
        self.assertEqual(_memory_max(), self.parsed["memory_limit"])
        resident = _rss(pid)
        charged = _memory_current()
        # Executable pages have to count against the same limit as the heap.
        # A charge well below RSS means the binary was still billed to another
        # cgroup, so a survival result would not describe the container.
        self.assertGreater(
            charged,
            int(resident * 0.85),
            "cgroup charged %d bytes but RSS is %d; memory limit is not applied to the process"
            % (charged, resident),
        )

    def _attack(self, path):
        if not internet_exposed(self.parsed):
            return
        _proc, pid, log_path = self._run_server()
        ready = _wait_until_listening(pid, self.port)
        log = open(log_path).read()
        self.assertTrue(ready, "vault never listened:\n%s" % log[-2000:])
        self._assert_accounted(pid)
        before = _cgroup_events()
        status, body, send_error, recv_error = _post_json(self.port, path, ATTACK_BODY_BYTES)
        time.sleep(0.4)
        after = _cgroup_events()
        alive = os.path.exists("/proc/%s" % pid)
        killed = (not alive) or after.get("oom_kill", 0) > before.get("oom_kill", 0)
        self.assertFalse(
            killed,
            "one anonymous POST %s of %d bytes killed vault under %d byte limit "
            "(status=%r body=%r send=%r recv=%r events %s -> %s)\n%s"
            % (
                path,
                ATTACK_BODY_BYTES,
                self.parsed["memory_limit"],
                status,
                body,
                send_error,
                recv_error,
                before,
                after,
                log[-1500:],
            ),
        )
        self.assertTrue(status.startswith("HTTP/1.1 4"), "expected a 4xx response, got %r %r" % (status, body))

    def test_unseal_survives_one_anonymous_oversized_post(self):
        self._attack("/v1/sys/unseal")

    def test_init_survives_one_anonymous_oversized_post(self):
        self._attack("/v1/sys/init")

    def test_seal_survives_one_anonymous_oversized_post(self):
        self._attack("/v1/sys/seal")

    def test_logical_survives_one_anonymous_oversized_post(self):
        self._attack("/v1/secret/foo")

    def test_unseal_accepts_anonymous_callers(self):
        # The crash above matters only if a caller without a token can reach
        # the parser. A tiny body must be parsed and rejected for its contents,
        # not refused as unauthenticated.
        if not internet_exposed(self.parsed):
            return
        _proc, pid, log_path = self._run_server()
        self.assertTrue(_wait_until_listening(pid, self.port), open(log_path).read()[-1500:])
        status, body, send_error, recv_error = _post_json(self.port, "/v1/sys/unseal", 20)
        self.assertTrue(
            os.path.exists("/proc/%s" % pid),
            "tiny unseal request killed vault: %s %s %s" % (status, send_error, recv_error),
        )
        self.assertIn("400", status, "anonymous unseal returned %r %r" % (status, body))
        self.assertNotIn("permission denied", body.lower())
        self.assertNotIn("401", status)


if __name__ == "__main__":
    unittest.main()
