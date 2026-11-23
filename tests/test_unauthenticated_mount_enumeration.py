#!/usr/bin/env python3
"""Spec for unauthenticated Vault mount enumeration.

These tests fail while this deployment is vulnerable. They pass once both of
the following are true:

1. The Vault server image in vault.yaml answers unauthenticated
   /v1/sys/internal/ui/mounts/<path> probes with the same status and the same
   body whether or not that path is a mounted secrets engine or auth method.
2. No Service manifest in this repo publishes Vault as an external load
   balancer that accepts traffic from the whole internet.

Run from the repository root:

    python3 tests/test_unauthenticated_mount_enumeration.py
"""

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WORLD_CIDRS = {"0.0.0.0/0", "::/0"}
SOURCE_RANGES_ANNOTATION = "service.beta.kubernetes.io/load-balancer-source-ranges"
INTERNAL_LB_ANNOTATION = "cloud.google.com/load-balancer-type"
PLACEHOLDER_TOKEN = "placeholder-token"

# Paths that resolve to a mount after the server enables database, aws, and userpass.
MOUNTED_PATHS = (
    "secret",
    "cubbyhole",
    "sys",
    "identity",
    "database",
    "aws",
    "auth/token",
    "auth/userpass",
    "secret/does-not-exist",
    "database/creds/missing-role",
    "auth/token/lookup",
    "auth/userpass/users/nobody",
)
UNMOUNTED_PATHS = (
    "not-a-mount",
    "gcp",
    "auth/ldap",
    "auth/does-not-exist",
    "not-a-mount/child",
)


def parse_yaml_documents(text):
    """Parse the small subset of YAML used by this repository's manifests."""
    documents = []
    current = []
    for line in text.splitlines():
        if line.strip() == "---":
            documents.append("\n".join(current))
            current = []
        else:
            current.append(line)
    documents.append("\n".join(current))
    return [parse_yaml_document(doc) for doc in documents if doc.strip()]


def parse_yaml_document(text):
    lines = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        lines.append((indent, raw.strip()))
    value, _ = parse_block(lines, 0, 0)
    return value


def parse_block(lines, index, indent):
    if index >= len(lines):
        return {}, index
    if lines[index][1].startswith("- "):
        return parse_list(lines, index, indent)
    return parse_map(lines, index, indent)


def parse_map(lines, index, indent):
    result = {}
    while index < len(lines):
        line_indent, text = lines[index]
        if line_indent < indent:
            break
        if line_indent > indent or text.startswith("- "):
            raise ValueError("unexpected YAML structure at %r" % text)
        key, _, rest = text.partition(":")
        rest = rest.strip()
        index += 1
        if rest in ("|", "|-", ">", ">-"):
            block, index = consume_literal(lines, index, line_indent)
            result[key] = block
            continue
        if rest == "":
            if index < len(lines) and lines[index][0] > line_indent:
                child, index = parse_block(lines, index, lines[index][0])
                result[key] = child
            else:
                result[key] = None
            continue
        result[key] = parse_scalar(rest)
    return result, index


def parse_list(lines, index, indent):
    result = []
    while index < len(lines):
        line_indent, text = lines[index]
        if line_indent < indent:
            break
        if line_indent != indent or not text.startswith("- "):
            break
        item = text[2:].strip()
        index += 1
        if item in ("|", "|-", ">", ">-"):
            block, index = consume_literal(lines, index, line_indent)
            result.append(block)
            continue
        if item == "":
            child, index = parse_block(lines, index, lines[index][0] if index < len(lines) else indent + 2)
            result.append(child)
            continue
        if ":" in item:
            key, _, rest = item.partition(":")
            rest = rest.strip()
            child = {}
            if rest in ("|", "|-", ">", ">-"):
                block, index = consume_literal(lines, index, line_indent)
                child[key] = block
            elif rest == "":
                if index < len(lines) and lines[index][0] > line_indent:
                    nested, index = parse_block(lines, index, lines[index][0])
                    child[key] = nested
                else:
                    child[key] = None
            else:
                child[key] = parse_scalar(rest)
            while index < len(lines) and lines[index][0] > line_indent and not lines[index][1].startswith("- "):
                extra, index = parse_map(lines, index, lines[index][0])
                child.update(extra)
            result.append(child)
            continue
        result.append(parse_scalar(item))
    return result, index


def consume_literal(lines, index, parent_indent):
    chunks = []
    while index < len(lines) and lines[index][0] > parent_indent:
        chunks.append(lines[index][1])
        index += 1
    return "\n".join(chunks), index


def parse_scalar(text):
    if (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'")):
        return text[1:-1]
    if text == "true":
        return True
    if text == "false":
        return False
    if text in ("null", "~"):
        return None
    if text.isdigit():
        return int(text)
    return text


def heredoc_bodies(text):
    bodies = []
    marker = None
    chunk = []
    for line in text.splitlines():
        if marker is None:
            if "<<" in line and "EOF" in line:
                marker = "EOF"
                chunk = []
            continue
        if line.strip() == marker:
            bodies.append("\n".join(chunk))
            marker = None
            chunk = []
            continue
        chunk.append(line)
    return bodies


def load_service_manifests():
    services = []
    sources = [("vault.yaml", (REPO_ROOT / "vault.yaml").read_text())]
    readme = (REPO_ROOT / "README.md").read_text()
    for index, body in enumerate(heredoc_bodies(readme)):
        sources.append(("README.md heredoc %d" % (index + 1), body))
    for name, text in sources:
        try:
            docs = parse_yaml_documents(text)
        except ValueError:
            if "kind: Service" not in text:
                continue
            raise
        for doc in docs:
            if isinstance(doc, dict) and doc.get("kind") == "Service":
                services.append((name, doc))
    return services


def source_ranges_of(service):
    spec = service.get("spec") or {}
    ranges = spec.get("loadBalancerSourceRanges") or []
    if ranges:
        return [str(item) for item in ranges]
    annotations = (service.get("metadata") or {}).get("annotations") or {}
    raw = annotations.get(SOURCE_RANGES_ANNOTATION) or ""
    return [part.strip() for part in str(raw).split(",") if part.strip()]


def is_external_world_load_balancer(service):
    spec = service.get("spec") or {}
    if spec.get("type") != "LoadBalancer":
        return False
    annotations = (service.get("metadata") or {}).get("annotations") or {}
    lb_type = str(annotations.get(INTERNAL_LB_ANNOTATION) or "")
    if lb_type.lower() == "internal":
        return False
    ranges = source_ranges_of(service)
    if not ranges:
        return True
    return any(cidr in WORLD_CIDRS for cidr in ranges)


def vault_image_tag():
    docs = parse_yaml_documents((REPO_ROOT / "vault.yaml").read_text())
    for doc in docs:
        if not isinstance(doc, dict) or doc.get("kind") != "StatefulSet":
            continue
        containers = (
            doc.get("spec", {})
            .get("template", {})
            .get("spec", {})
            .get("containers", [])
        )
        for container in containers:
            if container.get("name") == "vault":
                return container.get("image")
    raise AssertionError("vault.yaml has no container named vault")


def release_version(image):
    tag = str(image).rsplit(":", 1)[-1]
    if tag.startswith("v"):
        tag = tag[1:]
    parts = tag.split(".")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        raise AssertionError("vault image %r is not a released x.y.z tag" % image)
    return tag


def vault_binary(version):
    cache = Path(tempfile.gettempdir()) / "vault-mount-enum-bins" / version
    binary = cache / "vault"
    if binary.exists():
        return binary
    url = "https://releases.hashicorp.com/vault/%s/vault_%s_linux_amd64.zip" % (version, version)
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / "vault.zip"
    urllib.request.urlretrieve(url, archive)
    with zipfile.ZipFile(archive) as zipped:
        member = zipped.getinfo("vault")
        target = cache / "vault"
        with zipped.open(member) as source, open(target, "wb") as dest:
            shutil.copyfileobj(source, dest)
    os.chmod(target, 0o755)
    return binary


def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def http_json(method, url, payload=None, headers=None):
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request) as response:
            body = response.read()
            return response.status, body
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def normalized_body(body, path):
    text = body.decode()
    text = text.replace(path + "/", "MOUNT/")
    text = text.replace(path, "MOUNT")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return text
    return json.dumps(parsed, sort_keys=True)


def mount_probe_differences(base):
    probes = (
        ("GET", "", None, "no-token"),
        ("POST", "", {}, "no-token"),
        ("PUT", "", {}, "no-token"),
        ("DELETE", "", None, "no-token"),
        ("GET", "?list=true", None, "no-token"),
        ("GET", "?help=1", None, "no-token"),
        ("GET", "", {"X-Vault-Token": PLACEHOLDER_TOKEN}, "placeholder-token"),
        ("GET", "", {"X-Vault-Token": ""}, "empty-token"),
    )
    differences = []
    for method, query, headers, token_mode in probes:
        seen = {}
        for path in MOUNTED_PATHS + UNMOUNTED_PATHS:
            url = "%s/v1/sys/internal/ui/mounts/%s%s" % (base, path, query)
            status, body = http_json(method, url, None if method in ("GET", "DELETE") else {}, headers)
            signature = (status, normalized_body(body, path))
            seen.setdefault(signature, []).append(path)
        if len(seen) != 1:
            summary = {paths[0]: {"status": sig[0], "body": sig[1], "also": paths[1:]} for sig, paths in seen.items()}
            differences.append({"method": method, "query": query or "/", "token": token_mode, "groups": summary})
    return differences


class MountEnumerationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        image = vault_image_tag()
        version = release_version(image)
        binary = vault_binary(version)
        reported = subprocess.check_output([str(binary), "version"], text=True)
        if version not in reported:
            raise AssertionError("downloaded vault binary %r does not match image %s" % (reported.strip(), image))
        cls.server = VaultProcess(binary)
        cls.server.start()
        cls.base = cls.server.base_url
        status, body = http_json("PUT", cls.base + "/v1/sys/init", {"secret_shares": 1, "secret_threshold": 1})
        if status != 200:
            raise AssertionError("vault init failed with HTTP %s" % status)
        init = json.loads(body)
        status, body = http_json("PUT", cls.base + "/v1/sys/unseal", {"key": init["keys"][0]})
        if status != 200:
            raise AssertionError("vault unseal failed with HTTP %s" % status)
        seal = json.loads(body)
        if seal.get("sealed") is not False:
            raise AssertionError("vault remained sealed after unseal")
        token_header = {"X-Vault-Token": init["root_token"]}
        for path, mount_type in (("database", "database"), ("aws", "aws")):
            status, body = http_json("POST", cls.base + "/v1/sys/mounts/" + path, {"type": mount_type}, token_header)
            if status not in (200, 204):
                raise AssertionError("enabling %s secrets engine failed with HTTP %s" % (path, status))
        status, body = http_json("POST", cls.base + "/v1/sys/auth/userpass", {"type": "userpass"}, token_header)
        if status not in (200, 204):
            raise AssertionError("enabling userpass auth method failed with HTTP %s" % status)
        # The root token is only used to mount engines. Probes below send no token.

    @classmethod
    def tearDownClass(cls):
        server = getattr(cls, "server", None)
        if server is not None:
            server.stop()

    def test_unauthenticated_mount_probes_do_not_distinguish_mounts(self):
        differences = mount_probe_differences(self.base)
        self.assertFalse(
            differences,
            "unauthenticated /v1/sys/internal/ui/mounts probes reveal which mounts exist: %s" % json.dumps(differences),
        )

    def test_load_balancers_are_not_open_to_the_internet(self):
        services = load_service_manifests()
        self.assertTrue(services, "expected Vault Service manifests")
        open_services = []
        for origin, service in services:
            if is_external_world_load_balancer(service):
                name = (service.get("metadata") or {}).get("name")
                open_services.append("%s (%s)" % (name, origin))
        self.assertFalse(
            open_services,
            "external LoadBalancer Services accept traffic from the whole internet: %s" % ", ".join(open_services),
        )


class VaultProcess:
    def __init__(self, binary):
        self.binary = binary
        self.port = free_port()
        self.workdir = tempfile.TemporaryDirectory(prefix="vault-mount-enum-")
        self.proc = None

    @property
    def base_url(self):
        return "http://127.0.0.1:%d" % self.port

    def start(self):
        root = Path(self.workdir.name)
        config = root / "vault.hcl"
        data = root / "data"
        data.mkdir()
        config.write_text(
            "\n".join(
                (
                    "disable_mlock = true",
                    "ui = true",
                    'listener "tcp" {',
                    '  address = "127.0.0.1:%d"' % self.port,
                    "  tls_disable = 1",
                    "}",
                    'storage "file" {',
                    '  path = "%s"' % data,
                    "}",
                    "",
                )
            )
        )
        self.log = open(root / "server.log", "w")
        self.proc = subprocess.Popen(
            [str(self.binary), "server", "-config=" + str(config)],
            stdout=self.log,
            stderr=subprocess.STDOUT,
        )
        deadline = time.time() + 20
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise AssertionError("vault server exited early:\n" + (root / "server.log").read_text()[-2000:])
            try:
                status, _ = http_json("GET", self.base_url + "/v1/sys/seal-status")
            except urllib.error.URLError:
                status = 0
            if status:
                return
            time.sleep(0.1)
        raise AssertionError("vault server did not listen:\n" + (root / "server.log").read_text()[-2000:])

    def stop(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        log = getattr(self, "log", None)
        if log is not None and not log.closed:
            log.close()
        self.workdir.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
