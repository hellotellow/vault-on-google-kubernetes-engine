package pin

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// These tests are the spec for the unpinned vault-init image.
//
// They fail while vault.yaml schedules a container image by a mutable tag.
// They pass once every container in that pod is pinned to an image digest
// (image@sha256:...), including when imagePullPolicy stays Always, because
// the kubelet then pulls that digest instead of re-resolving a tag.
//
// Changing only imagePullPolicy is not a fix: IfNotPresent still pulls a tag
// on a node that does not already have it, and Always pulls a tag on every
// start. Setting command or args is not a fix either: Docker runs that
// command from the image filesystem, so a replaced image still supplies the
// process that receives Vault's init response.
//
// Not covered here, because this repository has nothing to assert them
// against: image-signature admission, and deleting the root token from the
// sidecar after initialization. Both live outside this manifest.

const (
	vaultZipURL  = "https://releases.hashicorp.com/vault/0.11.4/vault_0.11.4_linux_amd64.zip"
	vaultZipSHA  = "3e44826ffcf3756a72d6802d96ea244e605dad362ece27d5c8f8839fb69a7079"
	vaultVersion = "Vault v0.11.4"
)

type manifestDoc struct {
	Kind string `yaml:"kind"`
	Spec struct {
		Template struct {
			Spec podSpec `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

type podSpec struct {
	HostNetwork    bool        `yaml:"hostNetwork"`
	InitContainers []container `yaml:"initContainers"`
	Containers     []container `yaml:"containers"`
}

type container struct {
	Name            string   `yaml:"name"`
	Image           string   `yaml:"image"`
	ImagePullPolicy string   `yaml:"imagePullPolicy"`
	Command         []string `yaml:"command"`
	Args            []string `yaml:"args"`
	Env             []envVar `yaml:"env"`
}

type envVar struct {
	Name string `yaml:"name"`
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test file")
	}
	return filepath.Dir(filepath.Dir(file))
}

func loadVaultPod(t *testing.T) podSpec {
	t.Helper()
	path := filepath.Join(repoRoot(t), "vault.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vault.yaml: %v", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var doc manifestDoc
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("decode vault.yaml: %v", err)
		}
		if doc.Kind == "StatefulSet" {
			return doc.Spec.Template.Spec
		}
	}
	t.Fatal("vault.yaml has no StatefulSet")
	return podSpec{}
}

func TestDigestPinIsWhatTheKubeletPulls(t *testing.T) {
	pinned := "gcr.io/example/vault-init@sha256:" + strings.Repeat("ab", 32)
	ok, pulled, err := pullRefIsDigest(pinned)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("digest reference %q pulled as %q", pinned, pulled)
	}
	policy, err := effectivePullPolicy(pinned, "Always")
	if err != nil {
		t.Fatal(err)
	}
	if !shouldPullImage(policy, true) {
		t.Fatal("Always still contacts the registry when the image is already present")
	}
	// The registry request is for the digest, not a tag that can move.
	if !strings.Contains(pulled, "@sha256:") {
		t.Fatalf("pull reference %q dropped the digest", pulled)
	}

	floating := "gcr.io/hightowerlabs/vault-init"
	ok, pulled, err = pullRefIsDigest(floating)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatalf("untagged reference unexpectedly digested: %s", pulled)
	}
	policy, err = effectivePullPolicy(floating, "Always")
	if err != nil {
		t.Fatal(err)
	}
	if !shouldPullImage(policy, true) || !shouldPullImage(policy, false) {
		t.Fatal("Always must pull a floating tag whether or not a copy is cached")
	}
	policy, err = effectivePullPolicy(floating, "IfNotPresent")
	if err != nil {
		t.Fatal(err)
	}
	if shouldPullImage(policy, true) {
		t.Fatal("IfNotPresent does not re-pull a cached tag")
	}
	if !shouldPullImage(policy, false) {
		t.Fatal("IfNotPresent still resolves a tag on a node that has no copy")
	}
}

func TestVaultPodImagesStayPinnedAndInitHandsTheCallerTheRootToken(t *testing.T) {
	pod := loadVaultPod(t)
	if pod.HostNetwork {
		t.Fatal("vault pod sets hostNetwork, so containers would not share a pod network namespace")
	}

	// The sidecar's init request is unauthenticated and the response carries
	// the root token and every unseal share. Run that exchange against the
	// Vault version named by the pod before judging the image reference.
	assertInitHandsCallerUnsealMaterial(t)

	containers := append(append([]container{}, pod.InitContainers...), pod.Containers...)
	if len(containers) == 0 {
		t.Fatal("vault pod has no containers")
	}
	var problems []string
	for _, c := range containers {
		pulled, err := applyDefaultImageTag(c.Image)
		if err != nil {
			t.Fatalf("container %s image %q: %v", c.Name, c.Image, err)
		}
		_, tag, digest, err := parseImageName(c.Image)
		if err != nil {
			t.Fatalf("container %s image %q: %v", c.Name, c.Image, err)
		}
		policy, err := effectivePullPolicy(c.Image, c.ImagePullPolicy)
		if err != nil {
			t.Fatal(err)
		}
		immutable, _, err := pullRefIsDigest(c.Image)
		if err != nil {
			t.Fatal(err)
		}
		if !immutable {
			problems = append(problems, fmt.Sprintf(
				"%s image %q pulls %q policy %s (tag %q digest %q) present=%v absent=%v",
				c.Name, c.Image, pulled, policy, tag, digest,
				shouldPullImage(policy, true), shouldPullImage(policy, false),
			))
		}
	}
	if len(problems) > 0 {
		t.Fatalf("vault pod still runs mutable third-party images; pin each image to a digest:\n%s", strings.Join(problems, "\n"))
	}
}

func assertInitHandsCallerUnsealMaterial(t *testing.T) {
	t.Helper()
	bin := vaultBinary(t)
	dir := t.TempDir()
	port := freePort(t)
	cfg := filepath.Join(dir, "vault.hcl")
	body := fmt.Sprintf(`
listener "tcp" {
  address = "127.0.0.1:%d"
  tls_disable = 1
}
storage "file" {
  path = "%s"
}
disable_mlock = true
`, port, filepath.Join(dir, "data"))
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "server", "-config="+cfg)
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
	})

	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(20 * time.Second)
	var health int
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodHead, base+"/v1/sys/health", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err == nil {
			health = resp.StatusCode
			resp.Body.Close()
			if health != 0 {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if health != http.StatusNotImplemented {
		t.Fatalf("health before init = %d, want 501 (not initialized)", health)
	}

	// Same request body vault-init sends: secret_shares 5, secret_threshold 3.
	// No token header. The handler is mounted without authentication.
	initBody := []byte(`{"secret_shares":5,"secret_threshold":3}`)
	req, err := http.NewRequest(http.MethodPut, base+"/v1/sys/init", bytes.NewReader(initBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("init status = %d", resp.StatusCode)
	}
	var initResp struct {
		Keys       []string `json:"keys"`
		KeysBase64 []string `json:"keys_base64"`
		RootToken  string   `json:"root_token"`
	}
	if err := json.Unmarshal(raw, &initResp); err != nil {
		t.Fatalf("init response was not the expected object: %v", err)
	}
	if len(initResp.Keys) != 5 || len(initResp.KeysBase64) != 5 {
		t.Fatalf("init returned %d keys and %d keys_base64, want 5 and 5", len(initResp.Keys), len(initResp.KeysBase64))
	}
	if initResp.RootToken == "" {
		t.Fatal("init response root_token was empty")
	}
	for _, k := range initResp.KeysBase64 {
		if k == "" {
			t.Fatal("init response contained an empty unseal share")
		}
	}

	// Vault seals again after init. The same caller drives unseal with the
	// shares it just received, which is the request vault-init's unsealOne sends.
	sealed := true
	for _, share := range initResp.KeysBase64 {
		payload, err := json.Marshal(map[string]any{"key": share, "reset": false})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(http.MethodPut, base+"/v1/sys/unseal", bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("unseal status = %d", resp.StatusCode)
		}
		var unsealResp struct {
			Sealed bool `json:"sealed"`
		}
		if err := json.Unmarshal(raw, &unsealResp); err != nil {
			t.Fatalf("unseal response was not the expected object: %v", err)
		}
		sealed = unsealResp.Sealed
		if !sealed {
			break
		}
	}
	if sealed {
		t.Fatal("unseal shares from init did not unseal Vault")
	}
	// Drop the material before the function returns so a failure later in the
	// test cannot print it via a leftover value in an error formatter.
	for i := range initResp.Keys {
		initResp.Keys[i] = ""
	}
	for i := range initResp.KeysBase64 {
		initResp.KeysBase64[i] = ""
	}
	initResp.RootToken = ""
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func vaultBinary(t *testing.T) string {
	t.Helper()
	cache := filepath.Join(os.TempDir(), "vault-0.11.4-"+vaultZipSHA[:12])
	bin := filepath.Join(cache, "vault")
	if _, err := os.Stat(bin); err != nil {
		if err := os.MkdirAll(cache, 0o755); err != nil {
			t.Fatal(err)
		}
		resp, err := http.Get(vaultZipURL)
		if err != nil {
			t.Fatalf("download vault: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("download vault status = %d", resp.StatusCode)
		}
		zipBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(zipBytes)
		if hex.EncodeToString(sum[:]) != vaultZipSHA {
			t.Fatal("vault zip checksum mismatch")
		}
		zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, f := range zr.File {
			if f.Name != "vault" {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			out, err := os.OpenFile(bin, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
			if err != nil {
				rc.Close()
				t.Fatal(err)
			}
			_, err = io.Copy(out, rc)
			rc.Close()
			closeErr := out.Close()
			if err != nil {
				t.Fatal(err)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}
			found = true
			break
		}
		if !found {
			t.Fatal("vault zip did not contain the vault binary")
		}
	}
	out, err := exec.Command(bin, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("vault version: %v", err)
	}
	if !strings.Contains(string(out), vaultVersion) {
		t.Fatalf("vault binary is not %s", vaultVersion)
	}
	return bin
}
