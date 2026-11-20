"""Security spec for node-service-account credentials reaching every pod.

These tests fail while a pod on this cluster can mint the node service
account and use it to read and decrypt the Vault root token and unseal
keys. They pass once that identity can no longer do so.

The stand-ins follow the sources cited next to each step. They do not
call Google or a live cluster.

Run:
    python3 -m unittest discover -s tests -v
"""

import base64
import json
import os
import posixpath
import re
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import yaml

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))

# google-cloud-sdk 225.0.0 (2018-11-13), the SDK release current with
# GKE 1.11.2. api_lib/container/api_adapter.py lines 204-205 and 236-238.
SERVICE_ACCOUNT_SCOPES = (
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
)

# Same SDK, api_lib/compute/constants.py GKE_DEFAULT_SCOPES.
GKE_DEFAULT_SCOPES = (
    "https://www.googleapis.com/auth/devstorage.read_only",
    "https://www.googleapis.com/auth/logging.write",
    "https://www.googleapis.com/auth/monitoring",
    "https://www.googleapis.com/auth/service.management.readonly",
    "https://www.googleapis.com/auth/servicecontrol",
    "https://www.googleapis.com/auth/trace.append",
)

CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
KMS_SCOPE = "https://www.googleapis.com/auth/cloudkms"
STORAGE_READ_SCOPES = {
    "https://www.googleapis.com/auth/devstorage.read_only",
    "https://www.googleapis.com/auth/devstorage.read_write",
    "https://www.googleapis.com/auth/devstorage.full_control",
    CLOUD_PLATFORM_SCOPE,
}
KMS_SCOPES = {KMS_SCOPE, CLOUD_PLATFORM_SCOPE}

# Roles granted by the tutorial, from the current role references:
# roles/storage.objectAdmin includes storage.objects.get
# roles/cloudkms.cryptoKeyEncrypterDecrypter includes
# cloudkms.cryptoKeyVersions.useToDecrypt
ROLE_PERMISSIONS = {
    "objectAdmin": {"storage.objects.get", "storage.objects.list"},
    "legacyBucketReader": {"storage.buckets.get", "storage.objects.list"},
    "roles/cloudkms.cryptoKeyEncrypterDecrypter": {
        "cloudkms.cryptoKeyVersions.useToDecrypt",
        "cloudkms.cryptoKeyVersions.useToEncrypt",
    },
}

# Object names written by kelseyhightower/vault-init main.go initialize().
ROOT_TOKEN_OBJECT = "root-token.enc"
UNSEAL_KEYS_OBJECT = "unseal-keys.json.enc"

# Placeholder material. Not a credential.
ROOT_TOKEN_PLACEHOLDER = "vault-root-token-placeholder"
UNSEAL_KEYS_PLACEHOLDER = '{"keys_base64":["unseal-share-placeholder"]}'
TOKEN_PATH = "/computeMetadata/v1/instance/service-accounts/default/token"


def _join_continuations(text):
    lines = []
    buf = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        lines.append(buf.strip())
        buf = ""
    if buf.strip():
        lines.append(buf.strip())
    return lines


def _expand(text, env):
    def repl(match):
        return env.get(match.group(1), match.group(0))

    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", repl, text)


def load_deploy():
    """Parse the tutorial the operator runs and the pod manifest it applies."""
    with open(os.path.join(REPO_ROOT, "README.md"), encoding="utf-8") as handle:
        readme = handle.read()
    with open(os.path.join(REPO_ROOT, "vault.yaml"), encoding="utf-8") as handle:
        manifest = handle.read()
    env = {"PROJECT_ID": "vault-project"}
    commands = []
    for block in re.findall(r"```(?:\w+)?\n(.*?)```", readme, re.S):
        for line in _join_continuations(block):
            assignment = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)="(.*)"$', line)
            if assignment and assignment.group(1) != "PROJECT_ID":
                env[assignment.group(1)] = _expand(assignment.group(2), env)
            commands.append(_expand(line, env))

    project = env["PROJECT_ID"]
    node_sa = None
    scopes_arg = None
    metadata_mode = None
    node_taints = []
    bucket_bindings = []
    kms_bindings = []
    for cmd in commands:
        if cmd.startswith("gcloud container clusters create "):
            sa = re.search(r"--service-account\s+(\S+)", cmd)
            if sa:
                node_sa = sa.group(1)
            scopes = re.search(r"--scopes(?:=|\s+)(\S+)", cmd)
            if scopes:
                scopes_arg = scopes.group(1)
            mode = re.search(
                r"--workload-metadata(?:-from-node)?(?:=|\s+)(\S+)", cmd
            )
            if mode:
                metadata_mode = mode.group(1).upper()
            taints = re.search(r"--node-taints(?:=|\s+)(\S+)", cmd)
            if taints:
                node_taints = _parse_taints(taints.group(1))
        binding = re.search(
            r"gsutil iam ch\s+serviceAccount:(\S+):(\S+)\s+gs://(\S+)", cmd
        )
        if binding:
            bucket_bindings.append(
                {
                    "member": binding.group(1),
                    "role": binding.group(2),
                    "bucket": binding.group(3),
                }
            )
        if cmd.startswith("gcloud kms keys add-iam-policy-binding "):
            member = re.search(r"--member\s+serviceAccount:(\S+)", cmd)
            role = re.search(r"--role\s+(\S+)", cmd)
            if member and role:
                kms_bindings.append(
                    {
                        "member": member.group(1),
                        "role": role.group(1),
                        "key": _kms_key_resource(env),
                    }
                )

    # api_adapter.py NodeIdentityOptionsToNodeConfig: a service account
    # replaces whatever scopes were passed with cloud-platform and
    # userinfo.email. With no service account, --scopes defaults to
    # gke-default (flags.py AddNodeIdentityFlags).
    if node_sa:
        oauth_scopes = tuple(sorted(set(SERVICE_ACCOUNT_SCOPES)))
    elif scopes_arg:
        oauth_scopes = tuple(sorted(_expand_scopes(scopes_arg)))
    else:
        oauth_scopes = tuple(sorted(GKE_DEFAULT_SCOPES))
        node_sa = "{0}-compute@developer.gserviceaccount.com".format(project)

    # Flag omitted: gcloud 225 leaves workloadMetadataConfig unset
    # (api_adapter.py _AddWorkloadMetadataToNodeConfig). Kubernetes
    # 1.11.2 cluster/gce/config-default.sh defaults
    # ENABLE_METADATA_CONCEALMENT to false, so pod traffic is not
    # redirected to the concealment proxy.
    if metadata_mode in (None, "UNSPECIFIED"):
        metadata_mode = "EXPOSED"

    docs = list(yaml.safe_load_all(manifest))
    statefulset = next(doc for doc in docs if doc and doc.get("kind") == "StatefulSet")
    pod_spec = statefulset["spec"]["template"]["spec"]
    return {
        "project": project,
        "bucket": env["GCS_BUCKET_NAME"],
        "kms_key": _kms_key_resource(env),
        "node_sa": node_sa,
        "oauth_scopes": oauth_scopes,
        "metadata_mode": metadata_mode,
        "node_taints": node_taints,
        "bucket_bindings": bucket_bindings,
        "kms_bindings": kms_bindings,
        "vault_pod": _pod_from_spec("vault", pod_spec),
    }


def _kms_key_resource(env):
    return env.get(
        "KMS_KEY_ID",
        "projects/{0}/locations/global/keyRings/vault/cryptoKeys/vault-init".format(
            env["PROJECT_ID"]
        ),
    )


def _expand_scopes(scopes_arg):
    """ExpandScopeURIs for the aliases this tutorial can set."""
    aliases = {
        "gke-default": GKE_DEFAULT_SCOPES,
        "cloud-platform": (CLOUD_PLATFORM_SCOPE,),
        "storage-ro": ("https://www.googleapis.com/auth/devstorage.read_only",),
        "storage-rw": ("https://www.googleapis.com/auth/devstorage.read_write",),
        "storage-full": ("https://www.googleapis.com/auth/devstorage.full_control",),
        "cloudkms": (KMS_SCOPE,),
    }
    found = []
    for part in scopes_arg.split(","):
        found.extend(aliases.get(part, (part,)))
    return found


def _parse_taints(raw):
    taints = []
    for item in raw.split(","):
        body, _, effect = item.rpartition(":")
        key, _, value = body.partition("=")
        taints.append({"key": key, "value": value, "effect": effect or "NoSchedule"})
    return taints


def _pod_from_spec(name, spec):
    return {
        "name": name,
        "host_network": bool(spec.get("hostNetwork", False)),
        "tolerations": spec.get("tolerations") or [],
        "annotations": (spec.get("metadata") or {}).get("annotations") or {},
        "service_account_name": spec.get("serviceAccountName") or "default",
        "env": {
            env["name"]: env.get("value")
            for container in spec.get("containers") or []
            for env in container.get("env") or []
            if "value" in env
        },
    }


def _tolerates(toleration, taint):
    """k8s.io/api/core/v1 Toleration.ToleratesTaint at kubernetes v1.11.2."""
    effect = toleration.get("effect") or ""
    if effect and effect != taint["effect"]:
        return False
    key = toleration.get("key") or ""
    if key and key != taint["key"]:
        return False
    operator = toleration.get("operator") or "Equal"
    if operator == "Equal":
        return (toleration.get("value") or "") == taint["value"]
    if operator == "Exists":
        return True
    return False


def pod_schedulable(pod, taints):
    """PodToleratesNodeTaints at kubernetes v1.11.2 predicates.go:1516.

    NoSchedule and NoExecute taints must each be tolerated. An empty
    taint list admits every pod.
    """
    interesting = [t for t in taints if t["effect"] in ("NoSchedule", "NoExecute")]
    for taint in interesting:
        if not any(_tolerates(item, taint) for item in pod["tolerations"]):
            return False
    return True


def _clean_metadata_path(raw_path):
    """path.Clean from the metadata proxy, plus its trailing-slash rule."""
    if raw_path == "":
        return ""
    cleaned = posixpath.normpath(raw_path)
    if raw_path == "/":
        cleaned = ""
    if raw_path.endswith("/") and cleaned != "/":
        cleaned += "/"
    return cleaned


def concealment_filter(path, query_keys, headers):
    """GoogleCloudPlatform/k8s-metadata-proxy metadata.Filter.

    Returns the cleaned path, or raises PermissionError when the proxy
    would answer 403. The service-account token path is not concealed.
    kube-env and instance identity are.
    """
    if "X-Forwarded-For" in headers or "x-forwarded-for" in headers:
        raise PermissionError("X-Forwarded-For")
    cleaned = _clean_metadata_path(path)
    known_query = {
        "recursive",
        "alt",
        "wait_for_change",
        "timeout_sec",
        "last_etag",
        "service_account",
        "scope",
        "scopes",
        "audience",
        "licenses",
        "format",
    }
    for key in query_keys:
        if key not in known_query:
            raise PermissionError("unrecognized query")
    recursive_ok = any(
        re.search(pattern, cleaned)
        for pattern in (
            r"/0\.1/meta-data/service-accounts/.+/",
            r"/computeMetadata/v1beta1/instance/service-accounts/.+/",
            r"/computeMetadata/v1/instance/service-accounts/.+/",
        )
    )
    if "recursive" in query_keys and not recursive_ok:
        raise PermissionError("recursive")
    concealed_exact = {
        "/0.1/meta-data/attributes/kube-env",
        "/computeMetadata/v1beta1/instance/attributes/kube-env",
        "/computeMetadata/v1/instance/attributes/kube-env",
    }
    if cleaned in concealed_exact:
        raise PermissionError("concealed")
    concealed_patterns = (
        r"/0\.1/meta-data/service-accounts/.+/identity",
        r"/computeMetadata/v1beta1/instance/service-accounts/.+/identity",
        r"/computeMetadata/v1/instance/service-accounts/.+/identity",
    )
    if any(re.search(pattern, cleaned) for pattern in concealed_patterns):
        raise PermissionError("concealed")
    discovery = {
        "",
        "/",
        "/0.1",
        "/0.1/",
        "/0.1/meta-data",
        "/computeMetadata",
        "/computeMetadata/",
        "/computeMetadata/v1beta1",
        "/computeMetadata/v1",
    }
    if cleaned in discovery:
        return cleaned
    prefixes = (
        "/0.1/meta-data/",
        "/computeMetadata/v1beta1/",
        "/computeMetadata/v1/",
    )
    if any(cleaned.startswith(prefix) for prefix in prefixes):
        return cleaned
    raise PermissionError("api not allowed")


class _ClusterHandler(BaseHTTPRequestHandler):
    """Local stand-in for the metadata server, GCS object read, and KMS decrypt.

    The metadata response shape is the one
    golang.org/x/oauth2/google computeSource.Token (Vault 0.11.4 vendor)
    decodes: access_token, expires_in, token_type. Requests without
    Metadata-Flavor: Google are rejected, matching the v1 metadata API
    the same client calls.
    """

    cluster = None

    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path.startswith("/computeMetadata/") or path.startswith("/0.1/"):
            self._metadata(path)
            return
        if path.startswith("/storage/v1/b/"):
            self._storage_get(path)
            return
        if path.startswith("/vault/v1/"):
            self._vault_read(path)
            return
        self.send_error(404)

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        if path.endswith(":decrypt"):
            self._kms_decrypt(path, body)
            return
        self.send_error(404)

    def _metadata(self, path):
        mode = self.cluster["metadata_mode"]
        host_network = self.cluster["request_host_network"]
        # configure-helper.sh installs the DNAT to the proxy only when
        # concealment is enabled. hostNetwork pods are generated on the
        # host network namespace, so they do not traverse PREROUTING.
        use_proxy = mode == "SECURE" and not host_network
        if use_proxy:
            try:
                path = concealment_filter(path, [], dict(self.headers))
            except PermissionError as exc:
                self._json(403, {"error": str(exc)})
                return
        if path.startswith("/computeMetadata/") and self.headers.get(
            "Metadata-Flavor"
        ) != "Google":
            self._text(403, "Missing Metadata-Flavor: Google")
            return
        if path == TOKEN_PATH:
            token = self.cluster["mint_token"]()
            self._json(
                200,
                {
                    "access_token": token,
                    "expires_in": 3600,
                    "token_type": "Bearer",
                },
            )
            return
        self.send_error(404)

    def _caller(self):
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        return self.cluster["tokens"].get(header[len("Bearer ") :])

    def _storage_get(self, path):
        # storage.objects.get. Object Admin on the bucket includes it.
        match = re.match(r"^/storage/v1/b/([^/]+)/o/([^/]+)$", path)
        if not match:
            self.send_error(404)
            return
        bucket, name = match.group(1), match.group(2)
        caller = self._caller()
        if caller is None or not _scope_allows(caller["scopes"], "storage"):
            self._json(403, {"error": "insufficient scope"})
            return
        if not _iam_allows(
            self.cluster, caller["email"], "storage.objects.get", bucket=bucket
        ):
            self._json(403, {"error": "iam"})
            return
        payload = self.cluster["objects"].get((bucket, name))
        if payload is None:
            self.send_error(404)
            return
        self._json(200, {"name": name, "data": payload})

    def _kms_decrypt(self, path, body):
        caller = self._caller()
        if caller is None or not _scope_allows(caller["scopes"], "kms"):
            self._json(403, {"error": "insufficient scope"})
            return
        key = path[: -len(":decrypt")]
        key = key[len("/kms/v1/") :]
        if not _iam_allows(
            self.cluster,
            caller["email"],
            "cloudkms.cryptoKeyVersions.useToDecrypt",
            key=key,
        ):
            self._json(403, {"error": "iam"})
            return
        request = json.loads(body.decode("utf-8"))
        plaintext = self.cluster["decrypt"](request["ciphertext"])
        self._json(200, {"plaintext": plaintext})

    def _vault_read(self, path):
        # Vault 0.11.4: init's root token carries policy "root"
        # (token_store.go rootToken). PolicyStore.GetPolicy synthesizes
        # that policy, NewACL sets root, and AllowOperation allows every
        # path. The header is the token id, not a cloud access token.
        presented = self.headers.get("X-Vault-Token", "")
        if presented != self.cluster["root_token_id"]:
            self._json(403, {"errors": ["permission denied"]})
            return
        secret_path = path[len("/vault/v1/") :]
        self._json(200, {"data": self.cluster["secrets"].get(secret_path, {})})

    def _json(self, status, payload):
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _text(self, status, text):
        encoded = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def _scope_allows(scopes, api):
    """cloud-platform makes every GCP API in scope; narrower scopes do not.

    GoogleCloudPlatform/gke-secure-defaults-demo states that the
    cloud-platform scope allows any GCP API and that IAM then decides.
    Vault 0.11.4's GCS backend and vault-init otherwise require the
    storage and cloudkms scopes.
    """
    if api == "storage":
        return bool(set(scopes) & STORAGE_READ_SCOPES)
    if api == "kms":
        return bool(set(scopes) & KMS_SCOPES)
    return False


def _iam_allows(cluster, email, permission, bucket=None, key=None):
    if permission.startswith("storage."):
        for binding in cluster["bucket_bindings"]:
            if binding["member"] != email or binding["bucket"] != bucket:
                continue
            if permission in ROLE_PERMISSIONS.get(binding["role"], set()):
                return True
        return False
    if permission.startswith("cloudkms."):
        for binding in cluster["kms_bindings"]:
            if binding["member"] != email or binding["key"] != key:
                continue
            if permission in ROLE_PERMISSIONS.get(binding["role"], set()):
                return True
        return False
    return False


class ClusterFixture:
    def __init__(self, deploy):
        self.deploy = deploy
        root_b64 = base64.b64encode(ROOT_TOKEN_PLACEHOLDER.encode("utf-8")).decode(
            "ascii"
        )
        unseal_b64 = base64.b64encode(UNSEAL_KEYS_PLACEHOLDER.encode("utf-8")).decode(
            "ascii"
        )
        # vault-init stores the KMS ciphertext bytes of the base64 plaintext.
        self.objects = {
            (deploy["bucket"], ROOT_TOKEN_OBJECT): _fake_encrypt(root_b64),
            (deploy["bucket"], UNSEAL_KEYS_OBJECT): _fake_encrypt(unseal_b64),
        }
        self.tokens = {}
        self.serial = 0
        self.httpd = None
        self.base = None

    def mint_token(self):
        self.serial += 1
        token = "metadata-access-token-{0}".format(self.serial)
        self.tokens[token] = {
            "email": self.deploy["node_sa"],
            "scopes": self.deploy["oauth_scopes"],
        }
        return token

    def start(self):
        handler = type("Handler", (_ClusterHandler,), {})
        handler.cluster = {
            "metadata_mode": self.deploy["metadata_mode"],
            "request_host_network": False,
            "bucket_bindings": self.deploy["bucket_bindings"],
            "kms_bindings": self.deploy["kms_bindings"],
            "objects": self.objects,
            "tokens": self.tokens,
            "mint_token": self.mint_token,
            "decrypt": _fake_decrypt,
            "root_token_id": ROOT_TOKEN_PLACEHOLDER,
            "secrets": {"secret/my-secret": {"my-value": "stored-secret-placeholder"}},
        }
        self.handler_cluster = handler.cluster
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        thread.start()
        host, port = self.httpd.server_address
        self.base = "http://{0}:{1}".format(host, port)

    def stop(self):
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()

    def set_host_network(self, value):
        self.handler_cluster["request_host_network"] = value

    def set_metadata_mode(self, mode):
        self.handler_cluster["metadata_mode"] = mode


def _fake_encrypt(b64_plaintext):
    return "enc:" + b64_plaintext


def _fake_decrypt(ciphertext):
    if not ciphertext.startswith("enc:"):
        raise ValueError("ciphertext")
    return ciphertext[len("enc:") :]


def _request(url, headers=None, data=None, method=None):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def recover_vault_root(fixture, pod):
    """Run the attack path from one pod.

    Returns a dict with scheduled, recovered_root, recovered_unseal, and
    read_secret. A pod that cannot be scheduled never reaches the
    metadata server.
    """
    result = {
        "scheduled": pod_schedulable(pod, fixture.deploy["node_taints"]),
        "recovered_root": False,
        "recovered_unseal": False,
        "read_secret": False,
    }
    if not result["scheduled"]:
        return result
    # No GOOGLE_APPLICATION_CREDENTIALS is set on the pod. Vault 0.11.4's
    # GCS backend and vault-init then call the metadata server. On the
    # modes gcloud 225.0.0 can set (EXPOSED and SECURE), that server
    # returns the node service account even if a pod annotation names
    # some other account. Workload Identity is not part of this cluster
    # version.
    fixture.set_host_network(pod["host_network"])
    flavor = {"Metadata-Flavor": "Google"}
    status, body = _request(fixture.base + TOKEN_PATH, headers=flavor)
    if status != 200:
        return result
    token = json.loads(body.decode("utf-8"))["access_token"]
    auth = {"Authorization": "Bearer " + token}

    def read_object(name):
        status, raw = _request(
            "{0}/storage/v1/b/{1}/o/{2}".format(
                fixture.base, fixture.deploy["bucket"], name
            ),
            headers=auth,
        )
        if status != 200:
            return None
        return json.loads(raw.decode("utf-8"))["data"]

    def decrypt(ciphertext):
        payload = json.dumps({"ciphertext": ciphertext}).encode("utf-8")
        status, raw = _request(
            "{0}/kms/v1/{1}:decrypt".format(fixture.base, fixture.deploy["kms_key"]),
            headers={**auth, "Content-Type": "application/json"},
            data=payload,
            method="POST",
        )
        if status != 200:
            return None
        encoded = json.loads(raw.decode("utf-8"))["plaintext"]
        return base64.b64decode(encoded).decode("utf-8")

    root_ct = read_object(ROOT_TOKEN_OBJECT)
    if root_ct is not None:
        root = decrypt(root_ct)
        if root == ROOT_TOKEN_PLACEHOLDER:
            result["recovered_root"] = True
            vstatus, vraw = _request(
                fixture.base + "/vault/v1/secret/my-secret",
                headers={"X-Vault-Token": root},
            )
            if vstatus == 200 and json.loads(vraw.decode("utf-8")).get("data"):
                result["read_secret"] = True
    unseal_ct = read_object(UNSEAL_KEYS_OBJECT)
    if unseal_ct is not None:
        unseal = decrypt(unseal_ct)
        if unseal == UNSEAL_KEYS_PLACEHOLDER:
            result["recovered_unseal"] = True
    return result


class NodeServiceAccountMetadataTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.deploy = load_deploy()
        cls.fixture = ClusterFixture(cls.deploy)
        cls.fixture.start()

    @classmethod
    def tearDownClass(cls):
        cls.fixture.stop()

    def setUp(self):
        self.fixture.set_metadata_mode(self.deploy["metadata_mode"])

    def test_extra_pod_cannot_recover_root_token_or_unseal_keys(self):
        pod = {
            "name": "extra-workload",
            "host_network": False,
            "tolerations": [],
            "annotations": {},
            "service_account_name": "default",
            "env": {},
        }
        result = recover_vault_root(self.fixture, pod)
        self.assertFalse(
            result["recovered_root"] or result["recovered_unseal"] or result["read_secret"],
            "a non-vault pod recovered Vault root material: {0}".format(result),
        )

    def test_vault_container_cannot_recover_root_material_and_stays_schedulable(self):
        pod = self.deploy["vault_pod"]
        # The vault container env in vault.yaml has no root token. Recovery
        # has to come from the node metadata identity.
        self.assertNotIn("VAULT_TOKEN", pod["env"])
        result = recover_vault_root(self.fixture, pod)
        self.assertTrue(
            result["scheduled"],
            "the vault pod must remain schedulable on the cluster nodes",
        )
        self.assertFalse(result["recovered_root"])
        self.assertFalse(result["recovered_unseal"])
        self.assertFalse(result["read_secret"])

    def test_secure_concealment_alone_does_not_allow_recovery(self):
        # SECURE is the strongest metadata mode in gcloud 225.0.0. The
        # proxy still forwards the service-account token path.
        self.fixture.set_metadata_mode("SECURE")
        pod = {
            "name": "extra-workload",
            "host_network": False,
            "tolerations": [],
            "annotations": {},
            "service_account_name": "default",
            "env": {},
        }
        if not pod_schedulable(pod, self.deploy["node_taints"]):
            pod = self.deploy["vault_pod"]
        result = recover_vault_root(self.fixture, pod)
        self.assertTrue(result["scheduled"])
        self.assertFalse(result["recovered_root"])
        self.assertFalse(result["recovered_unseal"])
        self.assertFalse(result["read_secret"])


if __name__ == "__main__":
    unittest.main()
