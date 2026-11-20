"""Security spec for the public Vault API.

These tests fail while an unrestricted load balancer publishes a Vault
process whose root-generation, rekey, and unseal routes accept anonymous
callers. They pass once that path is closed: the Service no longer publishes
the API or cluster port without a source restriction, or the pinned server
rejects the anonymous call before it changes recovery state.

Run from the repository root:

    python3 -m unittest tests.test_anonymous_recovery_endpoints
"""

import hashlib
import json
import os
import platform
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
VAULT_YAML = REPO_ROOT / "vault.yaml"
README = REPO_ROOT / "README.md"
RELEASE_BASE = "https://releases.hashicorp.com/vault"
BINARY_CACHE = Path(tempfile.gettempdir()) / "vault-release-cache"
WORLD_CIDRS = {"0.0.0.0/0", "::/0"}
INTERNAL_LB_ANNOTATIONS = {
    "cloud.google.com/load-balancer-type": "internal",
    "networking.gke.io/load-balancer-type": "internal",
}
# Routes registered on the HTTP mux without a token check in Vault 0.11.4.
# sys/rekey/backup is not in this list: it is mounted on the logical sys
# handler. DR operation-token routes are not registered in this version.
AUTH_REJECTION = {401, 403}


def _documents(text):
    text = text.replace("${VAULT_LOAD_BALANCER_IP}", "192.0.2.10")
    return [doc for doc in yaml.safe_load_all(text) if isinstance(doc, dict)]


def services_in_vault_yaml():
    return [doc for doc in _documents(VAULT_YAML.read_text()) if doc.get("kind") == "Service"]


def services_in_readme():
    text = README.read_text()
    start = text.find("cat > vault-load-balancer.yaml <<EOF\n")
    if start < 0:
        return []
    body = text[start + len("cat > vault-load-balancer.yaml <<EOF\n") :]
    end = body.find("\nEOF")
    if end < 0:
        return []
    return [doc for doc in _documents(body[:end]) if doc.get("kind") == "Service"]


def deployed_services():
    return services_in_vault_yaml() + services_in_readme()


def _annotations(service):
    raw = (service.get("metadata") or {}).get("annotations") or {}
    return {str(key).lower(): str(value).lower() for key, value in raw.items()}


def unrestricted_public_service(service):
    """True when a Service publishes endpoints beyond the cluster with no
    client-network limit.

    Kubernetes exposes type LoadBalancer on an external load balancer and only
    applies spec.loadBalancerSourceRanges when that field is set. A GKE
    internal load balancer is selected with one of the internal annotations.
    """
    spec = service.get("spec") or {}
    service_type = spec.get("type") or "ClusterIP"
    if service_type not in ("LoadBalancer", "NodePort"):
        return False
    annotations = _annotations(service)
    for key, value in INTERNAL_LB_ANNOTATIONS.items():
        if annotations.get(key) == value:
            return False
    if service_type == "NodePort":
        return True
    ranges = [str(item) for item in (spec.get("loadBalancerSourceRanges") or [])]
    if not ranges:
        return True
    return any(item in WORLD_CIDRS for item in ranges)


def _port_matches(port, numbers, names):
    if port.get("port") in numbers or port.get("targetPort") in numbers:
        return True
    name = str(port.get("name") or "")
    return name in names


def service_publishes(service, numbers, names):
    if not unrestricted_public_service(service):
        return False
    ports = (service.get("spec") or {}).get("ports") or []
    return any(_port_matches(port, numbers, names) for port in ports)


def api_is_public():
    # vault.yaml publishes 443 -> 8200. The setup guide publishes 8200.
    return any(
        service_publishes(service, {443, 8200, "8200"}, {"vault-port", "http"})
        for service in deployed_services()
    )


def cluster_port_is_public():
    return any(
        service_publishes(service, {8201, "8201"}, {"server"})
        for service in deployed_services()
    )


def pinned_vault_version():
    for doc in _documents(VAULT_YAML.read_text()):
        containers = (
            ((doc.get("spec") or {}).get("template") or {}).get("spec") or {}
        ).get("containers") or []
        for container in containers:
            if container.get("name") != "vault":
                continue
            image = str(container.get("image") or "")
            name, _, tag = image.rpartition(":")
            if not tag or tag == "latest" or "/" in tag:
                raise AssertionError("vault container image %r has no release tag" % image)
            leaf = name.split("/")[-1]
            if leaf not in ("vault", ""):
                raise AssertionError("vault container image %r is not an official vault release" % image)
            return tag
    raise AssertionError("vault container not found in vault.yaml")


def _release_binary(version):
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine)
    if platform.system().lower() != "linux" or arch is None:
        raise AssertionError("this test runs the published linux vault binary; host is %s/%s" % (platform.system(), machine))
    archive = "vault_%s_linux_%s.zip" % (version, arch)
    cache_dir = BINARY_CACHE / version
    binary = cache_dir / "vault"
    if binary.exists():
        return binary
    cache_dir.mkdir(parents=True, exist_ok=True)
    sums_url = "%s/%s/vault_%s_SHA256SUMS" % (RELEASE_BASE, version, version)
    archive_url = "%s/%s/%s" % (RELEASE_BASE, version, archive)
    sums = urllib.request.urlopen(sums_url, timeout=60).read().decode()
    expected = None
    for line in sums.splitlines():
        digest, _, name = line.partition(" ")
        name = name.strip().lstrip("*")
        if name == archive:
            expected = digest.strip()
            break
    if not expected:
        raise AssertionError("no published checksum for %s" % archive)
    archive_path = cache_dir / archive
    archive_path.write_bytes(urllib.request.urlopen(archive_url, timeout=120).read())
    actual = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    if actual != expected:
        raise AssertionError("checksum mismatch for the published vault binary")
    with zipfile.ZipFile(archive_path) as zipped:
        zipped.extract("vault", path=cache_dir)
    binary.chmod(0o755)
    return binary


class VaultProcess:
    """One active Vault server using the release pinned by vault.yaml.

    The product listener is TLS on 0.0.0.0:8200 and the storage backend is
    GCS with HA. TLS wrapping does not authenticate the HTTP request, and the
    rekey, generate-root, and unseal progress this test checks live in the
    process, so the server here listens on loopback without TLS and uses a
    file backend. disable_mlock is set because this environment has no
    IPC_LOCK; the product manifest adds that capability instead.
    """

    def __init__(self):
        self.version = pinned_vault_version()
        self.binary = _release_binary(self.version)
        self.work = tempfile.TemporaryDirectory(prefix="vault-spec-")
        self.port = self._free_port()
        self.base = "http://127.0.0.1:%d" % self.port
        self.proc = None
        self._root_token = None
        self._keys = None

    def _free_port(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        return port

    def __enter__(self):
        config = self.work.name + "/vault.hcl"
        Path(config).write_text(
            "\n".join(
                [
                    "disable_mlock = true",
                    'listener "tcp" {',
                    '  address = "127.0.0.1:%d"' % self.port,
                    "  tls_disable = 1",
                    "}",
                    'storage "file" {',
                    '  path = "%s/data"' % self.work.name,
                    "}",
                    "",
                ]
            )
        )
        Path(self.work.name, "data").mkdir()
        log_path = Path(self.work.name, "server.log")
        self._log = log_path.open("w")
        self.proc = subprocess.Popen(
            [str(self.binary), "server", "-config=" + config],
            stdout=self._log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        deadline = time.time() + 20
        last = None
        while time.time() < deadline:
            if self.proc.poll() is not None:
                break
            status, _ = self.request("GET", "/v1/sys/health")
            last = status
            if status in (200, 429, 501, 503):
                health_status, health = self.request("GET", "/v1/sys/health")
                reported = (health or {}).get("version")
                if reported != self.version:
                    raise AssertionError(
                        "running server version %r does not match pinned image %s"
                        % (reported, self.version)
                    )
                return self
            time.sleep(0.05)
        raise AssertionError("vault %s did not start (last health %s)" % (self.version, last))

    def __exit__(self, exc_type, exc, tb):
        if self.proc is not None and self.proc.poll() is None:
            os.killpg(self.proc.pid, 15)
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, 9)
                self.proc.wait(timeout=5)
        self._log.close()
        self.work.cleanup()
        return False

    def request(self, method, path, body=None, token=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if body is not None:
            req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("X-Vault-Token", token)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                raw = resp.read()
                status = resp.status
        except urllib.error.HTTPError as err:
            raw = err.read()
            status = err.code
        except Exception:
            return None, {}
        if not raw:
            return status, {}
        try:
            parsed = json.loads(raw.decode())
        except Exception:
            return status, {}
        if not isinstance(parsed, dict):
            return status, {}
        return status, parsed

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def initialize_like_sidecar(self):
        """Same share counts the vault-init container sends to /v1/sys/init."""
        status, payload = self.request(
            "PUT",
            "/v1/sys/init",
            {"secret_shares": 5, "secret_threshold": 3},
        )
        if status != 200:
            raise AssertionError("test setup could not initialize vault (HTTP %s)" % status)
        self._keys = list(payload.get("keys_base64") or [])
        self._root_token = payload.get("root_token")
        if len(self._keys) != 5 or not self._root_token:
            raise AssertionError("test setup did not receive unseal shares")
        return self._keys

    def unseal_shares(self, count):
        progress = None
        sealed = None
        for key in self._keys[:count]:
            status, payload = self.request("PUT", "/v1/sys/unseal", {"key": key})
            if status != 200:
                raise AssertionError("test setup unseal failed (HTTP %s)" % status)
            progress = payload.get("progress")
            sealed = payload.get("sealed")
        return progress, sealed

    def root_token(self):
        return self._root_token

    def junk_share(self):
        import base64

        size = len(base64.b64decode(self._keys[0]))
        return base64.b64encode(b"\x11" * size).decode()


def _rejected(status):
    return status in AUTH_REJECTION


class PublicRecoveryEndpointTests(unittest.TestCase):
    def test_cluster_port_is_not_on_an_unrestricted_public_service(self):
        self.assertFalse(
            cluster_port_is_public(),
            "the setup guide publishes port 8201 on an unrestricted load balancer",
        )

    def test_anonymous_init_does_not_initialize_a_public_server(self):
        if not api_is_public():
            return
        with VaultProcess() as server:
            status, payload = server.request(
                "PUT",
                "/v1/sys/init",
                {"secret_shares": 5, "secret_threshold": 3},
            )
            initialized = status == 200 and bool(payload.get("root_token"))
            self.assertFalse(
                initialized,
                "anonymous PUT /v1/sys/init initialized the public server (HTTP %s)" % status,
            )

    def test_anonymous_unseal_reset_and_share_do_not_change_progress(self):
        if not api_is_public():
            return
        with VaultProcess() as server:
            server.initialize_like_sidecar()
            for method in ("POST", "PUT"):
                with self.subTest(method=method, body="reset"):
                    server.request("POST", "/v1/sys/unseal", {"reset": True})
                    _, sealed = server.unseal_shares(1)
                    self.assertTrue(sealed)
                    before = server.request("GET", "/v1/sys/seal-status")[1].get("progress")
                    self.assertEqual(before, 1)
                    status, _ = server.request(method, "/v1/sys/unseal", {"reset": True})
                    after = server.request("GET", "/v1/sys/seal-status")[1].get("progress")
                    self.assertTrue(
                        _rejected(status) and after == before,
                        "anonymous %s unseal reset changed progress %s -> %s (HTTP %s)"
                        % (method, before, after, status),
                    )
                with self.subTest(method=method, body="share"):
                    server.request("POST", "/v1/sys/unseal", {"reset": True})
                    server.unseal_shares(1)
                    before = server.request("GET", "/v1/sys/seal-status")[1].get("progress")
                    self.assertEqual(before, 1)
                    status, _ = server.request(
                        method, "/v1/sys/unseal", {"key": server.junk_share()}
                    )
                    after = server.request("GET", "/v1/sys/seal-status")[1].get("progress")
                    self.assertTrue(
                        _rejected(status) and after == before,
                        "anonymous %s unseal share changed progress %s -> %s (HTTP %s)"
                        % (method, before, after, status),
                    )

    def test_reset_between_sidecar_submissions_does_not_keep_vault_sealed(self):
        """vault-init submits each stored share in its own PUT /v1/sys/unseal."""
        if not api_is_public():
            return
        with VaultProcess() as server:
            keys = server.initialize_like_sidecar()
            for key in keys:
                status, _ = server.request("PUT", "/v1/sys/unseal", {"key": key})
                self.assertEqual(status, 200)
                reset_status, _ = server.request("POST", "/v1/sys/unseal", {"reset": True})
                if _rejected(reset_status):
                    continue
            _, seal = server.request("GET", "/v1/sys/seal-status")
            self.assertFalse(
                seal.get("sealed"),
                "interleaved anonymous unseal resets left the server sealed",
            )

    def test_anonymous_rekey_cannot_occupy_or_cancel_or_poison(self):
        if not api_is_public():
            return
        body = {"secret_shares": 5, "secret_threshold": 3}
        with VaultProcess() as server:
            server.initialize_like_sidecar()
            server.unseal_shares(3)
            for method in ("POST", "PUT"):
                with self.subTest(method=method, step="start"):
                    status, payload = server.request(method, "/v1/sys/rekey/init", body)
                    second_status, second = server.request("POST", "/v1/sys/rekey/init", body)
                    blocked = second_status == 400 and any(
                        "already in progress" in item for item in (second.get("errors") or [])
                    )
                    try:
                        self.assertTrue(
                            _rejected(status) and payload.get("started") is not True,
                            "anonymous %s /v1/sys/rekey/init was accepted (HTTP %s, follow-up blocked=%s)"
                            % (method, status, blocked),
                        )
                    finally:
                        server.request("DELETE", "/v1/sys/rekey/init", token=server.root_token())
            with self.subTest(step="cancel"):
                started, _ = server.request(
                    "POST", "/v1/sys/rekey/init", body, token=server.root_token()
                )
                self.assertEqual(started, 200)
                status, _ = server.request("DELETE", "/v1/sys/rekey/init")
                _, after = server.request(
                    "GET", "/v1/sys/rekey/init", token=server.root_token()
                )
                self.assertTrue(
                    _rejected(status) and after.get("started") is True,
                    "anonymous DELETE /v1/sys/rekey/init cancelled the in-progress rekey (HTTP %s, started %s)"
                    % (status, after.get("started")),
                )
            for method in ("POST", "PUT"):
                with self.subTest(method=method, step="update"):
                    server.request("DELETE", "/v1/sys/rekey/init", token=server.root_token())
                    started, current = server.request(
                        "POST", "/v1/sys/rekey/init", body, token=server.root_token()
                    )
                    self.assertEqual(started, 200)
                    before = current.get("progress")
                    status, _ = server.request(
                        method,
                        "/v1/sys/rekey/update",
                        {"key": server.junk_share(), "nonce": current.get("nonce")},
                    )
                    _, after = server.request(
                        "GET", "/v1/sys/rekey/init", token=server.root_token()
                    )
                    self.assertTrue(
                        _rejected(status) and after.get("progress") == before,
                        "anonymous %s rekey update changed progress %s -> %s (HTTP %s)"
                        % (method, before, after.get("progress"), status),
                    )

    def test_anonymous_rekey_verify_does_not_run(self):
        if not api_is_public():
            return
        with VaultProcess() as server:
            server.initialize_like_sidecar()
            server.unseal_shares(3)
            with self.subTest(step="delete-without-operation"):
                status, _ = server.request("DELETE", "/v1/sys/rekey/verify")
                self.assertTrue(server.alive(), "DELETE /v1/sys/rekey/verify stopped the server")
                self.assertTrue(
                    _rejected(status),
                    "anonymous DELETE /v1/sys/rekey/verify was not rejected (HTTP %s)" % status,
                )
            status, payload = server.request(
                "POST",
                "/v1/sys/rekey/init",
                {
                    "secret_shares": 5,
                    "secret_threshold": 3,
                    "require_verification": True,
                },
                token=server.root_token(),
            )
            self.assertEqual(status, 200)
            nonce = payload.get("nonce")
            for key in server._keys[:3]:
                status, _ = server.request(
                    "POST",
                    "/v1/sys/rekey/update",
                    {"key": key, "nonce": nonce},
                    token=server.root_token(),
                )
                self.assertIn(status, (200, 400))
            _, before = server.request("GET", "/v1/sys/rekey/verify", token=server.root_token())
            before_nonce = before.get("nonce")
            self.assertTrue(before_nonce)
            status, _ = server.request("DELETE", "/v1/sys/rekey/verify")
            _, after = server.request("GET", "/v1/sys/rekey/verify", token=server.root_token())
            self.assertTrue(
                _rejected(status) and after.get("nonce") == before_nonce,
                "anonymous DELETE /v1/sys/rekey/verify changed the verification operation (HTTP %s)"
                % status,
            )

    def test_anonymous_generate_root_cannot_occupy_or_cancel_or_poison(self):
        if not api_is_public():
            return
        with VaultProcess() as server:
            server.initialize_like_sidecar()
            server.unseal_shares(3)
            for method in ("POST", "PUT"):
                with self.subTest(method=method, step="start"):
                    status, payload = server.request(method, "/v1/sys/generate-root/attempt", {})
                    second_status, second = server.request(
                        "POST", "/v1/sys/generate-root/attempt", {}
                    )
                    blocked = second_status == 400 and any(
                        "already in progress" in item for item in (second.get("errors") or [])
                    )
                    try:
                        self.assertTrue(
                            _rejected(status) and payload.get("started") is not True,
                            "anonymous %s /v1/sys/generate-root/attempt was accepted (HTTP %s, follow-up blocked=%s)"
                            % (method, status, blocked),
                        )
                    finally:
                        server.request(
                            "DELETE",
                            "/v1/sys/generate-root/attempt",
                            token=server.root_token(),
                        )
            with self.subTest(step="cancel"):
                started, _ = server.request(
                    "POST",
                    "/v1/sys/generate-root/attempt",
                    {},
                    token=server.root_token(),
                )
                self.assertEqual(started, 200)
                status, _ = server.request("DELETE", "/v1/sys/generate-root/attempt")
                _, after = server.request(
                    "GET", "/v1/sys/generate-root/attempt", token=server.root_token()
                )
                self.assertTrue(
                    _rejected(status) and after.get("started") is True,
                    "anonymous DELETE /v1/sys/generate-root/attempt cancelled root generation (HTTP %s, started %s)"
                    % (status, after.get("started")),
                )
            for method in ("POST", "PUT"):
                with self.subTest(method=method, step="update"):
                    server.request(
                        "DELETE",
                        "/v1/sys/generate-root/attempt",
                        token=server.root_token(),
                    )
                    started, current = server.request(
                        "POST",
                        "/v1/sys/generate-root/attempt",
                        {},
                        token=server.root_token(),
                    )
                    self.assertEqual(started, 200)
                    before = current.get("progress")
                    status, _ = server.request(
                        method,
                        "/v1/sys/generate-root/update",
                        {"key": server.junk_share(), "nonce": current.get("nonce")},
                    )
                    _, after = server.request(
                        "GET", "/v1/sys/generate-root/attempt", token=server.root_token()
                    )
                    self.assertTrue(
                        _rejected(status) and after.get("progress") == before,
                        "anonymous %s generate-root update changed progress %s -> %s (HTTP %s)"
                        % (method, before, after.get("progress"), status),
                    )

    def test_anonymous_recovery_key_rekey_does_not_start_on_shamir(self):
        """This deployment has no seal stanza, so the barrier is Shamir and
        recovery-key rekey is rejected before a config is stored. The route is
        still unauthenticated; the assertion is that it must not occupy a slot.
        """
        if not api_is_public():
            return
        with VaultProcess() as server:
            server.initialize_like_sidecar()
            server.unseal_shares(3)
            for path in (
                "/v1/sys/rekey-recovery-key/init",
                "/v1/sys/rekey-recovery-key/update",
                "/v1/sys/rekey-recovery-key/verify",
            ):
                with self.subTest(path=path):
                    status, payload = server.request(
                        "POST",
                        path,
                        {"secret_shares": 5, "secret_threshold": 3, "key": server.junk_share(), "nonce": "x"},
                    )
                    _, rekey = server.request("GET", "/v1/sys/rekey/init", token=server.root_token())
                    self.assertFalse(payload.get("started") is True or rekey.get("started") is True)
                    self.assertNotEqual(status, 200)

    def test_anonymous_seal_does_not_seal_an_unsealed_server(self):
        if not api_is_public():
            return
        with VaultProcess() as server:
            server.initialize_like_sidecar()
            _, sealed = server.unseal_shares(3)
            self.assertFalse(sealed)
            status, _ = server.request("PUT", "/v1/sys/seal", {})
            _, after = server.request("GET", "/v1/sys/seal-status")
            self.assertFalse(after.get("sealed"), "anonymous seal sealed the server (HTTP %s)" % status)
            self.assertNotEqual(status, 200)
            self.assertNotEqual(status, 204)


if __name__ == "__main__":
    unittest.main()
