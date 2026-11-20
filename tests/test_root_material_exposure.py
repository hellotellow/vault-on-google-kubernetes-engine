"""Security spec for the production Vault bootstrap in this repository.

The deployment under test is the one described by README.md and vault.yaml:
vault-init (kelseyhightower/vault-init d9e854b29e8808a48d168d521ba257fae9299636,
the source of gcr.io/hightowerlabs/vault-init) initializes Vault 0.11.4, and
the IAM commands grant the GKE node service account access to the storage
bucket and the Cloud KMS key named in that deployment.

These tests fail while that node identity can recover a still-valid root
token or enough Shamir shares to pass the configured threshold. They pass
once the node identity can no longer do either.

Run from the repository root. The listener for the Cloud KMS and Cloud
Storage client calls binds port 443, so this needs root:

    sudo -n -E python3 -m unittest tests.test_root_material_exposure -v

No secret values are hard-coded. Runtime credentials are generated in a
temporary directory and are not printed.
"""

from __future__ import annotations

import base64
import email
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import textwrap
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from email import policy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

REPO_ROOT = Path(__file__).resolve().parents[1]
VAULT_VERSION = "0.11.4"
VAULT_INIT_COMMIT = "d9e854b29e8808a48d168d521ba257fae9299636"
PROJECT_ID = "vault-test-project"
HOSTS_MARKER = "# vault-root-exposure-test"
GOOGLE_HOSTS = (
    "cloudkms.googleapis.com",
    "storage.googleapis.com",
    "www.googleapis.com",
)
PLACEHOLDER_SECRET = "placeholder-secret-value"

# roles/cloudkms.cryptoKeyEncrypterDecrypter from
# https://cloud.google.com/kms/docs/reference/permissions-and-roles
# (Cloud KMS CryptoKey Encrypter/Decrypter).
KMS_ENCRYPT_DECRYPT_PERMS = frozenset(
    {
        "cloudkms.cryptoKeyVersions.useToDecrypt",
        "cloudkms.cryptoKeyVersions.useToEncrypt",
    }
)

# roles/storage.objectAdmin includes storage.objects.get and
# storage.objects.create. roles/storage.legacyBucketReader does not include
# storage.objects.get.
# https://cloud.google.com/storage/docs/access-control/iam-roles
STORAGE_ROLE_PERMS = {
    "roles/storage.objectAdmin": frozenset(
        {
            "storage.objects.get",
            "storage.objects.create",
            "storage.objects.delete",
            "storage.objects.list",
        }
    ),
    "roles/storage.legacyBucketReader": frozenset(
        {
            "storage.buckets.get",
            "storage.objects.list",
        }
    ),
}


def resolve_storage_role(role: str) -> str:
    """gsutil v4.46 gslib/utils/iam_helper.py ResolveRole."""
    if "roles/" in role:
        return role
    return "roles/storage.%s" % role


def continued_lines(text: str) -> list[str]:
    joined: list[str] = []
    buf = ""
    for line in text.splitlines():
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            buf += stripped[:-1].strip() + " "
            continue
        buf += stripped.strip()
        joined.append(buf.strip())
        buf = ""
    if buf:
        joined.append(buf.strip())
    return joined


def substitute_vars(text: str, variables: dict[str, str]) -> str:
    for name, value in variables.items():
        text = text.replace("${%s}" % name, value)
        text = text.replace("$%s" % name, value)
    return text


class Deployment:
    def __init__(self) -> None:
        readme = (REPO_ROOT / "README.md").read_text()
        manifest = (REPO_ROOT / "vault.yaml").read_text()
        variables = {
            "PROJECT_ID": PROJECT_ID,
        }
        for line in continued_lines(readme):
            if line.startswith("GCS_BUCKET_NAME=") or line.startswith("KMS_KEY_ID="):
                name, raw = line.split("=", 1)
                variables[name] = substitute_vars(raw.strip().strip('"'), variables)
        self.variables = variables
        self.bucket = variables["GCS_BUCKET_NAME"]
        self.kms_key = variables["KMS_KEY_ID"]
        self.bindings: list[dict] = []
        self.node_service_account = ""
        self.node_count = 0
        self.readme_revokes_root = "token revoke" in readme
        for line in continued_lines(readme):
            line = substitute_vars(line, variables)
            if line.startswith("gsutil iam ch "):
                parts = line.split()
                binding = parts[3]
                bucket_uri = parts[4]
                member, role = binding.rsplit(":", 1)
                bucket = bucket_uri[len("gs://") :]
                self.bindings.append(
                    {
                        "member": member,
                        "role": resolve_storage_role(role),
                        "resource": "bucket:" + bucket,
                    }
                )
            elif line.startswith("gcloud kms keys add-iam-policy-binding "):
                parts = line.split()
                key_name = parts[4]
                flags = _flags(parts[5:])
                resource = (
                    "projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s"
                    % (
                        flags["project"],
                        flags["location"],
                        flags["keyring"],
                        key_name,
                    )
                )
                self.bindings.append(
                    {
                        "member": flags["member"],
                        "role": flags["role"],
                        "resource": "kms:" + resource,
                    }
                )
            elif line.startswith("gcloud container clusters create "):
                flags = _flags(line.split()[4:])
                self.node_service_account = flags["service-account"]
                self.node_count = int(flags["num-nodes"])
        self.vault_init = _parse_vault_init(manifest)
        self.vault_hcl = _parse_vault_hcl(manifest)
        self.replicas = _parse_replicas(manifest)
        self.persists_shamir_material = bool(
            self.vault_init
            and "seal " not in self.vault_hcl
            and self.vault_init.get("gcs_bucket_from_config")
            and self.vault_init.get("kms_key_from_config")
        )

    def wired_bucket(self) -> str:
        if self.vault_init.get("gcs_bucket_from_config"):
            return self.bucket
        return self.vault_init.get("gcs_bucket_value", "")

    def wired_kms_key(self) -> str:
        if self.vault_init.get("kms_key_from_config"):
            return self.kms_key
        return self.vault_init.get("kms_key_value", "")

    def node_email(self) -> str:
        prefix = "serviceAccount:"
        account = self.node_service_account
        if account.startswith(prefix):
            return account[len(prefix) :]
        return account

    def member_has(self, member_email: str, permission: str, resource: str) -> bool:
        member = "serviceAccount:" + member_email
        for binding in self.bindings:
            if binding["member"] != member or binding["resource"] != resource:
                continue
            if binding["role"] in STORAGE_ROLE_PERMS:
                perms = STORAGE_ROLE_PERMS[binding["role"]]
            elif binding["role"] == "roles/cloudkms.cryptoKeyEncrypterDecrypter":
                perms = KMS_ENCRYPT_DECRYPT_PERMS
            else:
                perms = frozenset()
            if permission in perms:
                return True
        return False


def _flags(parts: list[str]) -> dict[str, str]:
    flags: dict[str, str] = {}
    index = 0
    while index < len(parts):
        token = parts[index]
        if token.startswith("--") and index + 1 < len(parts):
            flags[token[2:]] = parts[index + 1]
            index += 2
            continue
        index += 1
    return flags


def _parse_replicas(manifest: str) -> int:
    for line in manifest.splitlines():
        stripped = line.strip()
        if stripped.startswith("replicas:"):
            return int(stripped.split(":", 1)[1].strip())
    return 0


def _parse_vault_hcl(manifest: str) -> str:
    marker = "cat > /etc/vault/config/vault.hcl <<EOF"
    start = manifest.find(marker)
    if start < 0:
        return ""
    rest = manifest[start + len(marker) :]
    end = rest.find("\nEOF")
    if end < 0:
        return ""
    return rest[:end]


def _parse_vault_init(manifest: str) -> dict:
    lines = manifest.splitlines()
    for index, line in enumerate(lines):
        if line.strip() == "- name: vault-init":
            block = lines[index : index + 40]
            text = "\n".join(block)
            return {
                "present": True,
                "check_interval": _env_value(block, "CHECK_INTERVAL"),
                "gcs_bucket_from_config": "gcs_bucket_name" in text,
                "kms_key_from_config": "kms_key_id" in text,
                "gcs_bucket_value": _env_value(block, "GCS_BUCKET_NAME"),
                "kms_key_value": _env_value(block, "KMS_KEY_ID"),
            }
    return {}


def _env_value(block: list[str], name: str) -> str:
    for index, line in enumerate(block):
        if line.strip() == "- name: %s" % name:
            for follow in block[index + 1 : index + 4]:
                stripped = follow.strip()
                if stripped.startswith("value:"):
                    return stripped.split(":", 1)[1].strip().strip('"')
    return ""


class FakeGoogleState:
    def __init__(self, deployment: Deployment) -> None:
        self.deployment = deployment
        self.aes = AESGCM(AESGCM.generate_key(bit_length=256))
        self.objects: dict[tuple[str, str], bytes] = {}
        self.plaintext_by_ciphertext: dict[tuple[str, str], bytes] = {}
        self.tokens: dict[str, str] = {}
        self.decrypt_calls: list[dict] = []
        self.lock = threading.Lock()

    def issue_token(self, email: str) -> str:
        token = "test-access-token-%s" % base64.urlsafe_b64encode(os.urandom(18)).decode().rstrip("=")
        with self.lock:
            self.tokens[token] = email
        return token

    def email_for(self, authorization: str | None) -> str:
        if not authorization or not authorization.startswith("Bearer "):
            return ""
        token = authorization.split(" ", 1)[1].strip()
        with self.lock:
            return self.tokens.get(token, "")

    def allow(self, email: str, permission: str, resource: str) -> bool:
        return self.deployment.member_has(email, permission, resource)


class FakeGoogleHandler(BaseHTTPRequestHandler):
    state: FakeGoogleState

    def log_message(self, fmt: str, *args) -> None:
        return

    def do_POST(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        body = _read_body(self)
        host = self.headers.get("Host", "").split(":")[0]
        if path == "/token":
            self._token(body)
            return
        if host == "www.googleapis.com" and path.startswith("/upload/storage/"):
            self._insert_object(path, body)
            return
        if host == "cloudkms.googleapis.com" and path.endswith(":encrypt"):
            self._encrypt(path, body)
            return
        if host == "cloudkms.googleapis.com" and path.endswith(":decrypt"):
            self._decrypt(path, body)
            return
        self._json(404, {"error": {"code": 404, "message": "no such method"}})

    def do_GET(self) -> None:
        host = self.headers.get("Host", "").split(":")[0]
        if host != "storage.googleapis.com":
            self._json(404, {"error": {"code": 404, "message": "no such method"}})
            return
        path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
        bucket, _, name = path.lstrip("/").partition("/")
        email = self.state.email_for(self.headers.get("Authorization"))
        if not self.state.allow(email, "storage.objects.get", "bucket:" + bucket):
            self._json(403, {"error": {"code": 403, "message": "permission denied"}})
            return
        with self.state.lock:
            payload = self.state.objects.get((bucket, name))
        if payload is None:
            self._json(404, {"error": {"code": 404, "message": "not found"}})
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _token(self, body: bytes) -> None:
        form = urllib.parse.parse_qs(body.decode())
        assertion = form.get("assertion", [""])[0]
        payload_b64 = assertion.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload_b64))
        email = claims["iss"]
        token = self.state.issue_token(email)
        self._json(
            200,
            {"access_token": token, "token_type": "Bearer", "expires_in": 3600},
        )

    def _insert_object(self, path: str, body: bytes) -> None:
        marker = "/upload/storage/v1/b/"
        bucket = path[path.find(marker) + len(marker) :].split("/o", 1)[0]
        email = self.state.email_for(self.headers.get("Authorization"))
        if not self.state.allow(email, "storage.objects.create", "bucket:" + bucket):
            self._json(403, {"error": {"code": 403, "message": "permission denied"}})
            return
        metadata, media = _split_multipart(self.headers.get("Content-Type", ""), body)
        name = metadata.get("name")
        if not name:
            self._json(400, {"error": {"code": 400, "message": "object name required"}})
            return
        with self.state.lock:
            self.state.objects[(bucket, name)] = media
        self._json(200, {"bucket": bucket, "name": name, "size": str(len(media))})

    def _key_name(self, path: str) -> str:
        name = path
        if name.startswith("/v1/"):
            name = name[len("/v1/") :]
        for suffix in (":encrypt", ":decrypt"):
            if name.endswith(suffix):
                name = name[: -len(suffix)]
        return urllib.parse.unquote(name)

    def _encrypt(self, path: str, body: bytes) -> None:
        key_name = self._key_name(path)
        email = self.state.email_for(self.headers.get("Authorization"))
        if not self.state.allow(
            email, "cloudkms.cryptoKeyVersions.useToEncrypt", "kms:" + key_name
        ):
            self._json(403, {"error": {"code": 403, "message": "permission denied"}})
            return
        request = json.loads(body)
        raw = base64.b64decode(request["plaintext"])
        nonce = os.urandom(12)
        ciphertext = nonce + self.state.aes.encrypt(nonce, raw, key_name.encode())
        ciphertext_b64 = base64.b64encode(ciphertext).decode()
        with self.state.lock:
            self.state.plaintext_by_ciphertext[(key_name, ciphertext_b64)] = raw
        self._json(
            200,
            {
                "name": key_name + "/cryptoKeyVersions/1",
                "ciphertext": ciphertext_b64,
            },
        )

    def _decrypt(self, path: str, body: bytes) -> None:
        key_name = self._key_name(path)
        email = self.state.email_for(self.headers.get("Authorization"))
        request = json.loads(body)
        ciphertext = request.get("ciphertext", "")
        allowed = self.state.allow(
            email, "cloudkms.cryptoKeyVersions.useToDecrypt", "kms:" + key_name
        )
        with self.state.lock:
            self.state.decrypt_calls.append(
                {
                    "email": email,
                    "key": key_name,
                    "allowed": allowed,
                }
            )
            raw = self.state.plaintext_by_ciphertext.get((key_name, ciphertext))
        if not allowed:
            self._json(403, {"error": {"code": 403, "message": "permission denied"}})
            return
        if raw is None:
            self._json(400, {"error": {"code": 400, "message": "ciphertext mismatch"}})
            return
        self._json(200, {"plaintext": base64.b64encode(raw).decode()})

    def _json(self, status: int, payload: dict) -> None:
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def _read_body(handler: BaseHTTPRequestHandler) -> bytes:
    if handler.headers.get("Transfer-Encoding", "").lower() == "chunked":
        chunks = []
        while True:
            line = handler.rfile.readline()
            if not line:
                break
            size = int(line.split(b";", 1)[0], 16)
            if size == 0:
                handler.rfile.readline()
                break
            chunks.append(handler.rfile.read(size))
            handler.rfile.read(2)
        return b"".join(chunks)
    length = int(handler.headers.get("Content-Length", "0") or "0")
    if length == 0:
        return b""
    return handler.rfile.read(length)


def _split_multipart(content_type: str, body: bytes) -> tuple[dict, bytes]:
    message = email.message_from_bytes(
        ("Content-Type: %s\r\nMIME-Version: 1.0\r\n\r\n" % content_type).encode()
        + body,
        policy=policy.default,
    )
    metadata: dict = {}
    media = b""
    for part in message.walk():
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True) or b""
        content = part.get_content_type()
        if content == "application/json" and not metadata:
            metadata = json.loads(payload.decode() or "{}")
        else:
            media = payload
    return metadata, media


def _write_credentials(directory: Path, email: str, token_uri: str) -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path = directory / (email.split("@", 1)[0] + "-placeholder.json")
    path.write_text(
        json.dumps(
            {
                "type": "service_account",
                "client_email": email,
                "private_key": pem.decode(),
                "token_uri": token_uri,
                "project_id": PROJECT_ID,
            }
        )
    )
    return path


def _ensure_vault(cache: Path) -> Path:
    binary = cache / "vault"
    if binary.exists():
        return binary
    archive = cache / "vault.zip"
    url = (
        "https://releases.hashicorp.com/vault/%s/vault_%s_linux_amd64.zip"
        % (VAULT_VERSION, VAULT_VERSION)
    )
    urllib.request.urlretrieve(url, archive)
    subprocess.check_call(["unzip", "-o", str(archive), "-d", str(cache)])
    os.chmod(binary, 0o755)
    return binary


def _ensure_vault_init(cache: Path) -> Path:
    binary = cache / "vault-init"
    stamp = cache / "vault-init.commit"
    if binary.exists() and stamp.exists() and stamp.read_text().strip() == VAULT_INIT_COMMIT:
        return binary
    source = cache / "vault-init-src"
    if source.exists():
        shutil.rmtree(source)
    source.mkdir(parents=True)
    subprocess.check_call(["git", "init"], cwd=source)
    subprocess.check_call(
        ["git", "remote", "add", "origin", "https://github.com/kelseyhightower/vault-init.git"],
        cwd=source,
    )
    subprocess.check_call(
        ["git", "fetch", "--depth", "1", "origin", VAULT_INIT_COMMIT],
        cwd=source,
    )
    subprocess.check_call(["git", "checkout", "FETCH_HEAD"], cwd=source)
    commit = subprocess.check_output(
        ["git", "-c", "safe.directory=*", "-C", str(source), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    if commit != VAULT_INIT_COMMIT:
        raise RuntimeError("vault-init HEAD %s is not %s" % (commit, VAULT_INIT_COMMIT))
    gopath = cache / "gopath"
    pkg = gopath / "src" / "github.com" / "kelseyhightower" / "vault-init"
    if pkg.is_symlink() or pkg.exists():
        if pkg.is_symlink():
            pkg.unlink()
        else:
            shutil.rmtree(pkg)
    pkg.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, pkg)
    env = os.environ.copy()
    env["GO111MODULE"] = "off"
    env["GOPATH"] = str(gopath)
    subprocess.check_call(["go", "build", "-o", str(binary), "."], cwd=pkg, env=env)
    stamp.write_text(commit)
    return binary


def _make_ca(directory: Path) -> tuple[Path, Path]:
    ca_key = directory / "ca.key"
    ca_cert = directory / "ca.pem"
    subprocess.check_call(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(ca_key),
            "-out",
            str(ca_cert),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=vault-root-exposure-test",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return ca_cert, ca_key


def _sign_cert(directory: Path, ca_cert: Path, ca_key: Path, name: str, sans: str) -> tuple[Path, Path]:
    key = directory / ("%s.key" % name)
    csr = directory / ("%s.csr" % name)
    cert = directory / ("%s.crt" % name)
    ext = directory / ("%s.ext" % name)
    ext.write_text("subjectAltName=" + sans + "\n")
    subprocess.check_call(
        [
            "openssl",
            "req",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(csr),
            "-nodes",
            "-subj",
            "/CN=" + name,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.check_call(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(ca_cert),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-out",
            str(cert),
            "-days",
            "1",
            "-extfile",
            str(ext),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return cert, key


def _install_hosts() -> None:
    path = Path("/etc/hosts")
    existing = path.read_text()
    kept = "\n".join(line for line in existing.splitlines() if HOSTS_MARKER not in line)
    entry = "127.0.0.1 " + " ".join(GOOGLE_HOSTS) + " " + HOSTS_MARKER
    path.write_text(kept.rstrip() + "\n" + entry + "\n")


def _remove_hosts() -> None:
    path = Path("/etc/hosts")
    if not path.exists():
        return
    kept = "\n".join(line for line in path.read_text().splitlines() if HOSTS_MARKER not in line)
    path.write_text(kept.rstrip() + "\n")


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class AttackResult:
    def __init__(self) -> None:
        self.ran = False
        self.unrelated_denied = False
        self.single_decrypt_share_count = 0
        self.threshold = 0
        self.single_decrypt_includes_root = False
        self.readme_root_accepted = False
        self.init_root_accepted = False
        self.secret_readable = False
        self.secret_writable = False
        self.generate_root_complete = False
        self.replacement_root_accepted = False
        self.reseal_unseal_with_recovered_shares = False
        self.decrypt_call_count_for_shares = 0


class ExposureTest(unittest.TestCase):
    result: AttackResult
    deployment: Deployment

    @classmethod
    def setUpClass(cls) -> None:
        cls.deployment = Deployment()
        cls.result = AttackResult()
        if not _node_can_read_wrapped_material(cls.deployment):
            return
        cls.result = _run_configured_init(cls.deployment)

    @classmethod
    def tearDownClass(cls) -> None:
        return

    def test_node_identity_cannot_recover_root_token_or_unseal_shares(self) -> None:
        deployment = self.deployment
        readme = (REPO_ROOT / "README.md").read_text()
        if (
            deployment.persists_shamir_material
            and "cryptoKeyEncrypterDecrypter" in readme
            and "objectAdmin" in readme
            and not _node_can_read_wrapped_material(deployment)
        ):
            self.fail("parser missed the node service account IAM bindings")
        if not _node_can_read_wrapped_material(deployment):
            return

        result = self.result
        self.assertTrue(result.ran, "configured init path did not run")
        self.assertTrue(
            result.unrelated_denied,
            "harness granted decrypt to an identity the README does not authorize",
        )
        exposures = []
        if result.single_decrypt_includes_root or result.init_root_accepted:
            exposures.append("one decrypt of unseal-keys.json.enc returned a working root token")
        if result.readme_root_accepted:
            exposures.append("the README root-token.enc decrypt returned a working root token")
        if result.threshold and result.single_decrypt_share_count >= result.threshold:
            exposures.append(
                "one decrypt returned %d Shamir shares and the threshold is %d"
                % (result.single_decrypt_share_count, result.threshold)
            )
        if result.secret_readable or result.secret_writable:
            exposures.append("the recovered root token could read and write a secret")
        if result.generate_root_complete or result.replacement_root_accepted:
            exposures.append("the recovered shares completed generate-root")
        if result.reseal_unseal_with_recovered_shares:
            exposures.append("the recovered shares unsealed Vault after it was sealed")
        self.assertEqual(exposures, [])


def _node_can_read_wrapped_material(deployment: Deployment) -> bool:
    if not deployment.persists_shamir_material:
        return False
    email = deployment.node_email()
    return deployment.member_has(
        email,
        "cloudkms.cryptoKeyVersions.useToDecrypt",
        "kms:" + deployment.wired_kms_key(),
    ) and deployment.member_has(
        email,
        "storage.objects.get",
        "bucket:" + deployment.wired_bucket(),
    )


def _run_configured_init(deployment: Deployment) -> AttackResult:
    result = AttackResult()
    cache = Path(tempfile.gettempdir()) / "vault-root-exposure-cache"
    cache.mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="vault-root-exposure-"))
    vault_bin = _ensure_vault(cache)
    vault_init_bin = _ensure_vault_init(cache)
    ca_cert, ca_key = _make_ca(work)
    google_cert, google_key = _sign_cert(
        work,
        ca_cert,
        ca_key,
        "googleapis",
        "DNS:" + ",DNS:".join(GOOGLE_HOSTS),
    )
    vault_cert, vault_key = _sign_cert(
        work, ca_cert, ca_key, "vault", "DNS:localhost,IP:127.0.0.1"
    )
    token_port = _free_port()
    state = FakeGoogleState(deployment)
    node_email = deployment.node_email()
    _write_credentials(work, node_email, "http://127.0.0.1:%d/token" % token_port)
    unrelated_email = "unrelated@%s.iam.gserviceaccount.com" % PROJECT_ID
    _write_credentials(work, unrelated_email, "http://127.0.0.1:%d/token" % token_port)

    server = ThreadingHTTPServer(("127.0.0.1", token_port), FakeGoogleHandler)
    server.state_holder = state
    FakeGoogleHandler.state = state
    token_thread = threading.Thread(target=server.serve_forever, daemon=True)
    token_thread.start()

    tls = ThreadingHTTPServer(("127.0.0.1", 443), FakeGoogleHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(google_cert, google_key)
    tls.socket = context.wrap_socket(tls.socket, server_side=True)
    FakeGoogleHandler.state = state
    tls_thread = threading.Thread(target=tls.serve_forever, daemon=True)

    vault_proc = None
    init_proc = None
    vault_log = None
    init_log = None
    hosts_installed = False
    tls_started = False
    try:
        _install_hosts()
        hosts_installed = True
        tls_thread.start()
        tls_started = True
        storage = work / "vault-data"
        storage.mkdir()
        hcl = work / "vault.hcl"
        hcl.write_text(
            textwrap.dedent(
                """
                listener "tcp" {
                  address = "127.0.0.1:8200"
                  tls_cert_file = "%s"
                  tls_key_file = "%s"
                  tls_min_version = "tls12"
                }
                storage "file" {
                  path = "%s"
                }
                disable_mlock = true
                ui = true
                """
                % (vault_cert, vault_key, storage)
            )
        )
        vault_log = open(work / "vault.log", "w")
        init_log_path = work / "vault-init.log"
        init_log = open(init_log_path, "w")
        vault_proc = subprocess.Popen(
            [str(vault_bin), "server", "-config", str(hcl)],
            stdout=vault_log,
            stderr=subprocess.STDOUT,
        )
        _wait_for_port("127.0.0.1", 8200)
        env = os.environ.copy()
        env.update(
            {
                "VAULT_ADDR": "https://127.0.0.1:8200",
                "CHECK_INTERVAL": deployment.vault_init.get("check_interval") or "10",
                "GCS_BUCKET_NAME": deployment.wired_bucket(),
                "KMS_KEY_ID": deployment.wired_kms_key(),
                "GOOGLE_APPLICATION_CREDENTIALS": str(work / (node_email.split("@", 1)[0] + "-placeholder.json")),
                "SSL_CERT_FILE": str(ca_cert),
                "GODEBUG": "netdns=go",
            }
        )
        init_proc = subprocess.Popen(
            [str(vault_init_bin)],
            stdout=init_log,
            stderr=subprocess.STDOUT,
            env=env,
        )
        _wait_for_objects(state, deployment.wired_bucket(), vault_proc, init_proc, init_log_path)
        if init_proc.poll() is None:
            init_proc.kill()
            init_proc.wait(timeout=10)
        result.ran = True
        _exercise_attack(deployment, state, result, node_email, unrelated_email, work, ca_cert)
        return result
    finally:
        for proc in (init_proc, vault_proc):
            if proc is not None and proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
        if tls_started:
            tls.shutdown()
        tls.server_close()
        server.shutdown()
        server.server_close()
        for handle in (vault_log, init_log):
            if handle is not None:
                handle.close()
        if hosts_installed:
            _remove_hosts()
        shutil.rmtree(work, ignore_errors=True)


def _wait_for_port(host: str, port: int) -> None:
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError("timed out waiting for %s:%d" % (host, port))


def _wait_for_objects(state, bucket, vault_proc, init_proc, log_path: Path) -> None:
    deadline = time.time() + 40
    while time.time() < deadline:
        if vault_proc.poll() is not None:
            raise RuntimeError("vault exited early")
        if init_proc.poll() is not None:
            raise RuntimeError("vault-init exited early:\n" + log_path.read_text()[-4000:])
        with state.lock:
            names = {name for stored_bucket, name in state.objects if stored_bucket == bucket}
        if "root-token.enc" in names and "unseal-keys.json.enc" in names:
            log_text = log_path.read_text()
            if "Vault is initialized and unsealed." in log_text or "Unseal complete." in log_text:
                return
        time.sleep(0.25)
    raise RuntimeError("vault-init did not store key material:\n" + log_path.read_text()[-4000:])


def _exercise_attack(deployment, state, result, node_email, unrelated_email, work, ca_cert) -> None:
    context = ssl.create_default_context(cafile=str(ca_cert))
    node_token = _access_token(node_email, work)
    other_token = _access_token(unrelated_email, work)
    bucket = deployment.wired_bucket()
    key_name = deployment.wired_kms_key()

    root_object = _gcs_get(context, node_token, bucket, "root-token.enc")
    share_object = _gcs_get(context, node_token, bucket, "unseal-keys.json.enc")
    unrelated_status, _ = _kms_decrypt(
        context,
        other_token,
        key_name,
        share_object.decode(),
    )
    result.unrelated_denied = unrelated_status == 403
    calls_before = len(state.decrypt_calls)
    share_status, share_plaintext = _kms_decrypt(
        context,
        node_token,
        key_name,
        share_object.decode(),
    )
    result.decrypt_call_count_for_shares = len(state.decrypt_calls) - calls_before
    if share_status == 200:
        decoded = base64.b64decode(share_plaintext)
        payload = json.loads(decoded)
        shares = payload.get("keys_base64") or []
        result.single_decrypt_share_count = len(shares)
        root_from_shares = payload.get("root_token") or ""
        result.single_decrypt_includes_root = bool(root_from_shares)
    else:
        shares = []
        root_from_shares = ""

    raw_root_ciphertext = base64.b64decode(root_object)
    readme_status, readme_plaintext = _kms_decrypt(
        context,
        node_token,
        key_name,
        base64.b64encode(raw_root_ciphertext).decode(),
    )
    readme_root = base64.b64decode(readme_plaintext).decode() if readme_status == 200 else ""

    vault = _VaultClient()
    status = vault.request("GET", "/v1/sys/seal-status")
    result.threshold = int(status.get("t") or 0)
    if root_from_shares:
        looked = vault.request(
            "GET", "/v1/auth/token/lookup-self", token=root_from_shares
        )
        result.init_root_accepted = looked.get("_status") == 200
    if readme_root:
        looked = vault.request("GET", "/v1/auth/token/lookup-self", token=readme_root)
        result.readme_root_accepted = looked.get("_status") == 200

    root_token = root_from_shares or readme_root
    if result.init_root_accepted or result.readme_root_accepted:
        mounted = vault.request(
            "POST",
            "/v1/sys/mounts/secret",
            token=root_token,
            body={"type": "kv", "options": {"version": "2"}},
        )
        written = vault.request(
            "POST",
            "/v1/secret/data/my-secret",
            token=root_token,
            body={"data": {"my-value": PLACEHOLDER_SECRET}},
        )
        read_back = vault.request("GET", "/v1/secret/data/my-secret", token=root_token)
        data = ((read_back.get("data") or {}).get("data") or {})
        result.secret_writable = written.get("_status") in (200, 204)
        result.secret_readable = data.get("my-value") == PLACEHOLDER_SECRET and mounted.get("_status") in (
            200,
            204,
        )

    if shares:
        otp, nonce = _generate_root_start(vault)
        encoded = ""
        complete = False
        for share in shares:
            progress = vault.request(
                "PUT",
                "/v1/sys/generate-root/update",
                body={"Nonce": nonce, "Key": share},
            )
            complete = bool(progress.get("complete"))
            encoded = progress.get("encoded_root_token") or progress.get("encoded_token") or ""
            if complete:
                break
        result.generate_root_complete = complete
        if complete and encoded and otp:
            replacement = _xor_otp(encoded, otp)
            looked = vault.request(
                "GET", "/v1/auth/token/lookup-self", token=replacement
            )
            result.replacement_root_accepted = looked.get("_status") == 200

        if root_token:
            vault.request("PUT", "/v1/sys/seal", token=root_token)
            unsealed = False
            for share in shares:
                progress = vault.request(
                    "PUT",
                    "/v1/sys/unseal",
                    body={"key": share, "reset": False},
                )
                if progress.get("sealed") is False:
                    unsealed = True
                    break
            result.reseal_unseal_with_recovered_shares = unsealed


def _access_token(email: str, work: Path) -> str:
    creds = json.loads((work / (email.split("@", 1)[0] + "-placeholder.json")).read_text())
    header = {"alg": "RS256", "typ": "JWT"}
    now = int(time.time())
    claims = {
        "iss": creds["client_email"],
        "scope": "https://www.googleapis.com/auth/cloudkms",
        "aud": creds["token_uri"],
        "iat": now,
        "exp": now + 3600,
    }
    segments = [
        base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("="),
        base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("="),
    ]
    key = serialization.load_pem_private_key(creds["private_key"].encode(), password=None)
    signature = key.sign(
        ".".join(segments).encode(),
        padding_pkcs1v15(),
        hashes_sha256(),
    )
    segments.append(base64.urlsafe_b64encode(signature).decode().rstrip("="))
    assertion = ".".join(segments)
    data = urllib.parse.urlencode(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
        }
    ).encode()
    request = urllib.request.Request(creds["token_uri"], data=data)
    with urllib.request.urlopen(request, timeout=5) as response:
        payload = json.loads(response.read())
    return payload["access_token"]


def padding_pkcs1v15():
    from cryptography.hazmat.primitives.asymmetric import padding

    return padding.PKCS1v15()


def hashes_sha256():
    from cryptography.hazmat.primitives import hashes

    return hashes.SHA256()


def _kms_decrypt(context: ssl.SSLContext, token: str, key_name: str, ciphertext_b64: str):
    url = "https://cloudkms.googleapis.com/v1/%s:decrypt?alt=json" % key_name
    data = json.dumps({"ciphertext": ciphertext_b64}).encode()
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, context=context, timeout=5) as response:
            body = json.loads(response.read())
            return response.status, body.get("plaintext", "")
    except urllib.error.HTTPError as error:
        return error.code, ""


def _gcs_get(context: ssl.SSLContext, token: str, bucket: str, name: str) -> bytes:
    url = "https://storage.googleapis.com/%s/%s" % (bucket, name)
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(request, context=context, timeout=5) as response:
        return response.read()


class _VaultClient:
    def request(self, method: str, path: str, token: str = "", body: dict | None = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            "https://127.0.0.1:8200" + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        if token:
            request.add_header("X-Vault-Token", token)
        context = ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(request, context=context, timeout=5) as response:
                raw = response.read()
                payload = json.loads(raw) if raw else {}
                payload["_status"] = response.status
                return payload
        except urllib.error.HTTPError as error:
            raw = error.read()
            try:
                payload = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                payload = {}
            payload["_status"] = error.code
            return payload


def _generate_root_start(vault: _VaultClient) -> tuple[str, str]:
    started = vault.request("PUT", "/v1/sys/generate-root/attempt", body={})
    return started.get("otp") or "", started.get("nonce") or ""


def _xor_otp(encoded: str, otp: str) -> str:
    padded = encoded + "=" * (-len(encoded) % 4)
    raw = base64.urlsafe_b64decode(padded)
    mixed = bytes(a ^ b for a, b in zip(raw, otp.encode()))
    return mixed.decode()


def _serve_as_root_if_needed() -> bool:
    if os.geteuid() == 0:
        return False
    if os.environ.get("VAULT_EXPOSURE_REEXEC") == "1":
        raise SystemExit("re-exec as root did not change euid")
    script = str(Path(__file__).resolve())
    env = os.environ.copy()
    env["VAULT_EXPOSURE_REEXEC"] = "1"
    command = ["sudo", "-n", "-E", sys_executable(), script] + sys_argv()
    raise SystemExit(subprocess.call(command, env=env))


def sys_executable() -> str:
    return os.environ.get("VAULT_EXPOSURE_PYTHON", os.sys.executable)


def sys_argv() -> list[str]:
    return os.sys.argv[1:]


if __name__ == "__main__":
    _serve_as_root_if_needed()
    unittest.main(verbosity=2)
