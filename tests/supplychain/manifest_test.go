package supplychain

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	dockerref "github.com/docker/distribution/reference"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"gopkg.in/yaml.v3"
)

// These tests are the spec for the unpinned busybox init container that writes
// Vault's server configuration. They fail while that deployment is vulnerable
// and pass once the images are digest-pinned and Vault's configuration is no
// longer produced by an image-supplied shell.

const (
	pullAlways       = "Always"
	pullIfNotPresent = "IfNotPresent"
	defaultImageTag  = "latest"

	// Placeholder only. The metadata stand-in never returns a real credential.
	placeholderNodeToken = "PLACEHOLDER_NODE_ACCESS_TOKEN"

	attackerListener = "0.0.0.0:9"
	attackerStorage  = "file"
)

func TestPodImagesAreDigestPinned(t *testing.T) {
	pod := mustLoadVaultPod(t)
	for _, c := range allContainers(pod) {
		repo, tag, digest, policy := mustResolveImage(t, c)
		if digest == "" {
			t.Errorf("container %q image %q resolves to %s:%s with pull policy %s and no digest; a publisher of that tag can replace the code this pod runs",
				c.Name, c.Image, repo, tag, policy)
		}
	}
}

func TestShellInitContainersAreNonRootWithReadOnlyRootFS(t *testing.T) {
	pod := mustLoadVaultPod(t)
	// API-server defaulting installs an empty pod security context before the
	// kubelet reads the spec. kubernetes v1.11.2 pkg/apis/core/v1/defaults.go
	// SetDefaults_PodSpec. The effective user is computed from that defaulted
	// spec, so a fix has to set runAsNonRoot on the container itself.
	if pod.Spec.SecurityContext == nil {
		pod.Spec.SecurityContext = &podSecurityContext{}
	}
	for _, c := range pod.Spec.InitContainers {
		if !containerSuppliesShell(c) {
			continue
		}
		bare := c
		bare.SecurityContext = nil
		barePod := pod
		barePod.Spec.SecurityContext = &podSecurityContext{}
		if uid, _ := effectiveUID(barePod, bare, ""); uid != 0 {
			t.Fatalf("harness: empty image user for %q resolved to uid %d, want 0 from kubelet getImageUser", c.Name, uid)
		}
		uid, _ := effectiveUID(pod, c, "")
		ro := c.SecurityContext != nil && c.SecurityContext.ReadOnlyRootFilesystem != nil && *c.SecurityContext.ReadOnlyRootFilesystem
		nonRoot := c.SecurityContext != nil && c.SecurityContext.RunAsNonRoot != nil && *c.SecurityContext.RunAsNonRoot
		user := int64(0)
		if c.SecurityContext != nil && c.SecurityContext.RunAsUser != nil {
			user = *c.SecurityContext.RunAsUser
		}
		if !nonRoot || user == 0 || !ro {
			t.Errorf("init container %q effective uid %d, runAsNonRoot=%v, runAsUser=%d, readOnlyRootFilesystem=%v; an image-supplied shell must set runAsNonRoot, a non-zero runAsUser, and a read-only root filesystem",
				c.Name, uid, nonRoot, user, ro)
		}
	}
}

func TestVaultServerConfigComesFromConfigMapNotImageShell(t *testing.T) {
	pod := mustLoadVaultPod(t)
	vault := mustContainer(t, pod.Spec.Containers, "vault")
	configPath := vaultConfigPath(t, vault)
	vol, mount := volumeForMount(t, pod, configDir(configPath), vault)
	if mount.MountPath != configDir(configPath) && configPath != mount.MountPath && !strings.HasPrefix(configPath, strings.TrimRight(mount.MountPath, "/")+"/") {
		t.Fatalf("harness: mount %q does not cover config path %q", mount.MountPath, configPath)
	}
	writer := shellWriter(pod, configPath)
	loaded := loadedConfig{}
	if writer != nil {
		written := runImageSuppliedShell(t, writer)
		loaded = mustParseVaultConfig(t, written)
		if loaded.StorageType != attackerStorage || loaded.ListenerAddress != attackerListener {
			t.Fatalf("harness: image-supplied shell output did not parse as the attacker config (storage %q listener %q)", loaded.StorageType, loaded.ListenerAddress)
		}
	}
	if vol.ConfigMap == nil || writer != nil {
		who := "none"
		image := ""
		if writer != nil {
			who = writer.Name
			image = writer.Image
		}
		t.Fatalf("Vault server loads %s from volume %q (configMap=%v) written by container %q image %q. An image-supplied /bin/sh can replace that file; Vault 0.11.4 ParseConfig then reads storage %q listener %q. Mount the server config from a ConfigMap and do not let a container shell write it.",
			configPath, vol.Name, vol.ConfigMap != nil, who, image, loaded.StorageType, loaded.ListenerAddress)
	}
	if !configMapProvidesFile(t, vol.ConfigMap.Name, filepath.Base(configPath)) {
		t.Fatalf("ConfigMap %q must provide %s for the vault server to load", vol.ConfigMap.Name, filepath.Base(configPath))
	}
}

func TestMutableImageCannotMintDecryptingNodeToken(t *testing.T) {
	pod := mustLoadVaultPod(t)
	readme := mustReadRepoFile(t, "README.md")
	nodeSA, scopes, roles := nodeCredential(t, readme)
	if !scopeAllowsKMSDecrypt(scopes) || !rolesAllowDecryptAndObjectRead(roles) {
		t.Fatalf("harness: node credential is not the decrypting vault-server account described by the README (sa %q scopes %v roles %v)", nodeSA, scopes, roles)
	}

	var mutable []resolvedContainer
	for _, c := range allContainers(pod) {
		repo, tag, digest, policy := mustResolveImage(t, c)
		if digest == "" && (policy == pullAlways || tag == defaultImageTag) {
			mutable = append(mutable, resolvedContainer{container: c, repo: repo, tag: tag, policy: policy})
		}
	}
	body, status := requestMetadataToken(t)
	if status != http.StatusOK || !strings.Contains(body, placeholderNodeToken) {
		t.Fatalf("harness: metadata stand-in did not issue a token (%d %s)", status, body)
	}
	if len(mutable) == 0 {
		return
	}
	names := make([]string, 0, len(mutable))
	for _, c := range mutable {
		names = append(names, fmt.Sprintf("%s (%s:%s, %s)", c.Name, c.repo, c.tag, c.policy))
	}
	t.Fatalf("mutable images %s run in the vault pod and can request a node metadata token for %s. That token's scopes %v include cloud-platform, which Cloud KMS decrypt accepts, and the service account holds %v (storage.objects.get and cloudkms.cryptoKeyVersions.useToDecrypt).",
		strings.Join(names, ", "), nodeSA, scopes, roles)
}

type resolvedContainer struct {
	container
	repo   string
	tag    string
	policy string
}

type podSecurityContext struct {
	RunAsUser    *int64 `yaml:"runAsUser"`
	RunAsNonRoot *bool  `yaml:"runAsNonRoot"`
}

type securityContext struct {
	RunAsUser              *int64 `yaml:"runAsUser"`
	RunAsNonRoot           *bool  `yaml:"runAsNonRoot"`
	ReadOnlyRootFilesystem *bool  `yaml:"readOnlyRootFilesystem"`
	Capabilities           *struct {
		Add []string `yaml:"add"`
	} `yaml:"capabilities"`
}

type envVar struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

type volumeMount struct {
	Name      string `yaml:"name"`
	MountPath string `yaml:"mountPath"`
}

type container struct {
	Name            string           `yaml:"name"`
	Image           string           `yaml:"image"`
	ImagePullPolicy string           `yaml:"imagePullPolicy"`
	Command         []string         `yaml:"command"`
	Args            []string         `yaml:"args"`
	Env             []envVar         `yaml:"env"`
	SecurityContext *securityContext `yaml:"securityContext"`
	VolumeMounts    []volumeMount    `yaml:"volumeMounts"`
}

type configMapVol struct {
	Name string `yaml:"name"`
}

type volume struct {
	Name      string        `yaml:"name"`
	EmptyDir  *struct{}     `yaml:"emptyDir"`
	ConfigMap *configMapVol `yaml:"configMap"`
	Secret    *struct {
		SecretName string `yaml:"secretName"`
	} `yaml:"secret"`
}

type podSpec struct {
	SecurityContext *podSecurityContext `yaml:"securityContext"`
	InitContainers  []container         `yaml:"initContainers"`
	Containers      []container         `yaml:"containers"`
	Volumes         []volume            `yaml:"volumes"`
}

type pod struct {
	Spec podSpec `yaml:"spec"`
}

type statefulSet struct {
	Kind string `yaml:"kind"`
	Spec struct {
		Template pod `yaml:"template"`
	} `yaml:"spec"`
}

func allContainers(p pod) []container {
	out := make([]container, 0, len(p.Spec.InitContainers)+len(p.Spec.Containers))
	out = append(out, p.Spec.InitContainers...)
	out = append(out, p.Spec.Containers...)
	return out
}

func mustLoadVaultPod(t *testing.T) pod {
	t.Helper()
	raw := mustReadRepoFile(t, "vault.yaml")
	for _, doc := range strings.Split(raw, "\n---\n") {
		var set statefulSet
		if err := yaml.Unmarshal([]byte(doc), &set); err != nil {
			t.Fatalf("parse vault.yaml: %v", err)
		}
		if set.Kind == "StatefulSet" {
			return set.Spec.Template
		}
	}
	t.Fatal("vault.yaml has no StatefulSet")
	return pod{}
}

func mustReadRepoFile(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(file), "..", "..", name)
	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(buf)
}

func mustContainer(t *testing.T, containers []container, name string) container {
	t.Helper()
	for _, c := range containers {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("container %q not found", name)
	return container{}
}

// parseImageName is kubernetes v1.11.2 pkg/util/parsers/parsers.go ParseImageName.
// The repository parse is github.com/docker/distribution/reference at
// edc3ab29cdff8694dd6feb85cfeb4b5f1b38ed9c, the revision vendored by that
// Kubernetes release (Godeps rev edc3ab29).
func parseImageName(image string) (string, string, string, error) {
	named, err := dockerref.ParseNormalizedNamed(image)
	if err != nil {
		return "", "", "", fmt.Errorf("couldn't parse image name: %v", err)
	}
	repoToPull := named.Name()
	var tag, digest string
	if tagged, ok := named.(dockerref.Tagged); ok {
		tag = tagged.Tag()
	}
	if digested, ok := named.(dockerref.Digested); ok {
		digest = digested.Digest().String()
	}
	if len(tag) == 0 && len(digest) == 0 {
		tag = defaultImageTag
	}
	return repoToPull, tag, digest, nil
}

// defaultPullPolicy is kubernetes v1.11.2 pkg/apis/core/v1/defaults.go
// SetDefaults_Container. An empty policy with tag latest becomes Always.
func defaultPullPolicy(image, policy string) (string, error) {
	if policy != "" {
		return policy, nil
	}
	_, tag, _, err := parseImageName(image)
	if err != nil {
		return "", err
	}
	if tag == defaultImageTag {
		return pullAlways, nil
	}
	return pullIfNotPresent, nil
}

// applyDefaultImageTag is kubernetes v1.11.2 pkg/kubelet/images/image_manager.go
// applyDefaultImageTag. Untagged names gain ":latest" before the pull.
func applyDefaultImageTag(image string) (string, error) {
	named, err := dockerref.ParseNormalizedNamed(image)
	if err != nil {
		return "", err
	}
	_, isTagged := named.(dockerref.Tagged)
	_, isDigested := named.(dockerref.Digested)
	if !isTagged && !isDigested {
		image = image + ":" + defaultImageTag
	}
	return image, nil
}

// shouldPullImage is kubernetes v1.11.2 pkg/kubelet/images/image_manager.go
// shouldPullImage. PullAlways pulls even when the image is already present.
func shouldPullImage(policy string, imagePresent bool) bool {
	if policy == "Never" {
		return false
	}
	if policy == pullAlways || (policy == pullIfNotPresent && !imagePresent) {
		return true
	}
	return false
}

func mustResolveImage(t *testing.T, c container) (repo, tag, digest, policy string) {
	t.Helper()
	var err error
	repo, tag, digest, err = parseImageName(c.Image)
	if err != nil {
		t.Fatalf("parse image %q: %v", c.Image, err)
	}
	policy, err = defaultPullPolicy(c.Image, c.ImagePullPolicy)
	if err != nil {
		t.Fatalf("default pull policy %q: %v", c.Image, err)
	}
	pulled, err := applyDefaultImageTag(c.Image)
	if err != nil {
		t.Fatalf("apply default tag %q: %v", c.Image, err)
	}
	if digest == "" && tag == defaultImageTag && !strings.HasSuffix(pulled, ":"+defaultImageTag) {
		t.Fatalf("harness: default tag was not applied to %q (%s)", c.Image, pulled)
	}
	if policy == pullAlways && !shouldPullImage(policy, true) {
		t.Fatalf("harness: Always policy did not pull when the image was already present")
	}
	return repo, tag, digest, policy
}

// effectiveUID follows kubernetes v1.11.2:
//   - dockershim/helpers.go getUserFromImageUser: an empty image user yields a nil uid
//   - kuberuntime/helpers.go getImageUser: a nil uid and empty username is treated as root (new(int64))
//   - securitycontext/util.go DetermineEffectiveSecurityContext: a container runAsUser overrides the pod
//   - kuberuntime/security_context.go determineEffectiveSecurityContext: a nil runAsUser is filled from the image uid
//   - kuberuntime/security_context.go verifyRunAsNonRoot: a nil runAsNonRoot allows uid 0
//   - dockershim/security_context.go modifyContainerConfig: a set runAsUser becomes the docker User string
func effectiveUID(pod pod, c container, imageUser string) (int64, string) {
	imageUID, imageName := userFromImageUser(imageUser)
	var uid *int64
	username := ""
	if imageUID != nil {
		uid = imageUID
	} else if imageName != "" {
		username = imageName
	} else {
		root := int64(0)
		uid = &root
	}
	effective := securityContextFromPod(pod)
	if c.SecurityContext != nil && c.SecurityContext.RunAsUser != nil {
		v := *c.SecurityContext.RunAsUser
		effective = &securityContext{RunAsUser: &v, RunAsNonRoot: c.SecurityContext.RunAsNonRoot, ReadOnlyRootFilesystem: c.SecurityContext.ReadOnlyRootFilesystem}
	} else if c.SecurityContext != nil && c.SecurityContext.RunAsNonRoot != nil {
		if effective == nil {
			effective = &securityContext{}
		}
		v := *c.SecurityContext.RunAsNonRoot
		effective.RunAsNonRoot = &v
	}
	runAs := (*int64)(nil)
	if effective != nil {
		runAs = effective.RunAsUser
	}
	if runAs == nil && uid != nil {
		runAs = uid
	}
	nonRoot := effective != nil && effective.RunAsNonRoot != nil && *effective.RunAsNonRoot
	if nonRoot && runAs != nil && *runAs == 0 {
		return *runAs, "rejected-by-runAsNonRoot"
	}
	if runAs == nil {
		return -1, username
	}
	return *runAs, username
}

func userFromImageUser(imageUser string) (*int64, string) {
	user := imageUser
	if i := strings.Index(user, ":"); i >= 0 {
		user = user[:i]
	}
	if user == "" {
		return nil, ""
	}
	var uid int64
	if _, err := fmt.Sscan(user, &uid); err != nil {
		return nil, user
	}
	if !strings.ContainsAny(user, "0123456789") {
		return nil, user
	}
	// Numeric uid, matching strconv.ParseInt success.
	n, err := parseInt(user)
	if err != nil {
		return nil, user
	}
	return &n, ""
}

func parseInt(s string) (int64, error) {
	var n int64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not numeric")
		}
		n = n*10 + int64(r-'0')
	}
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	return n, nil
}

func securityContextFromPod(p pod) *securityContext {
	if p.Spec.SecurityContext == nil {
		return nil
	}
	sc := &securityContext{}
	if p.Spec.SecurityContext.RunAsUser != nil {
		v := *p.Spec.SecurityContext.RunAsUser
		sc.RunAsUser = &v
	}
	if p.Spec.SecurityContext.RunAsNonRoot != nil {
		v := *p.Spec.SecurityContext.RunAsNonRoot
		sc.RunAsNonRoot = &v
	}
	return sc
}

func containerSuppliesShell(c container) bool {
	if len(c.Command) > 0 && (c.Command[0] == "/bin/sh" || c.Command[0] == "sh") {
		return true
	}
	for _, arg := range c.Args {
		if strings.Contains(arg, "/bin/sh") {
			return true
		}
	}
	return false
}

func vaultConfigPath(t *testing.T, c container) string {
	t.Helper()
	for _, arg := range c.Args {
		if strings.HasPrefix(arg, "-config=") {
			return strings.TrimPrefix(arg, "-config=")
		}
	}
	t.Fatal("vault container args do not set -config")
	return ""
}

func configDir(path string) string {
	return filepath.Dir(path)
}

func volumeForMount(t *testing.T, p pod, dir string, c container) (volume, volumeMount) {
	t.Helper()
	var mount volumeMount
	found := false
	for _, m := range c.VolumeMounts {
		if m.MountPath == dir || strings.HasPrefix(dir, strings.TrimRight(m.MountPath, "/")+"/") {
			mount = m
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no volume mount covers %s", dir)
	}
	for _, v := range p.Spec.Volumes {
		if v.Name == mount.Name {
			return v, mount
		}
	}
	t.Fatalf("volume %q not found", mount.Name)
	return volume{}, mount
}

type configMapDoc struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Data map[string]string `yaml:"data"`
}

func configMapProvidesFile(t *testing.T, name, file string) bool {
	t.Helper()
	raw := mustReadRepoFile(t, "vault.yaml")
	for _, doc := range strings.Split(raw, "\n---\n") {
		var cm configMapDoc
		if err := yaml.Unmarshal([]byte(doc), &cm); err != nil {
			t.Fatalf("parse vault.yaml: %v", err)
		}
		if cm.Kind == "ConfigMap" && cm.Metadata.Name == name && strings.TrimSpace(cm.Data[file]) != "" {
			return true
		}
	}
	return false
}

func shellWriter(p pod, configPath string) *container {
	for i := range p.Spec.InitContainers {
		c := &p.Spec.InitContainers[i]
		if commandWrites(c, configPath) {
			return c
		}
	}
	for i := range p.Spec.Containers {
		c := &p.Spec.Containers[i]
		if commandWrites(c, configPath) {
			return c
		}
	}
	return nil
}

func commandWrites(c *container, configPath string) bool {
	text := strings.Join(append(append([]string{}, c.Command...), c.Args...), "\n")
	return strings.Contains(text, configPath) && (strings.Contains(text, ">") || strings.Contains(text, "cat "))
}

type loadedConfig struct {
	StorageType     string
	ListenerAddress string
}

// mustParseVaultConfig follows hashicorp/vault v0.11.4 command/server/config.go
// LoadConfigFile, ParseConfig, ParseStorage, and parseListeners, using
// github.com/hashicorp/hcl at 65a6292f0157eff210d03ed1bf6c59b190b8b906
// (vendor/vendor.json in that Vault release).
func mustParseVaultConfig(t *testing.T, hclText string) loadedConfig {
	t.Helper()
	obj, err := hcl.Parse(hclText)
	if err != nil {
		t.Fatalf("hcl parse: %v", err)
	}
	list, ok := obj.Node.(*ast.ObjectList)
	if !ok {
		t.Fatal("hcl root is not an object list")
	}
	var loaded loadedConfig
	if o := list.Filter("storage"); len(o.Items) > 0 {
		item := o.Items[0]
		if len(item.Keys) == 0 {
			t.Fatal("storage block has no type")
		}
		key, ok := item.Keys[0].Token.Value().(string)
		if !ok {
			t.Fatal("storage type is not a string")
		}
		loaded.StorageType = strings.ToLower(key)
	}
	if o := list.Filter("listener"); len(o.Items) > 0 {
		item := o.Items[0]
		var m map[string]interface{}
		if err := hcl.DecodeObject(&m, item.Val); err != nil {
			t.Fatalf("decode listener: %v", err)
		}
		addr, _ := m["address"].(string)
		loaded.ListenerAddress = addr
	}
	return loaded
}

func runImageSuppliedShell(t *testing.T, writer *container) string {
	t.Helper()
	if len(writer.Command) == 0 || writer.Command[0] != "/bin/sh" {
		t.Fatalf("harness: writer command is %v, want /bin/sh", writer.Command)
	}
	dir := t.TempDir()
	rootfs := filepath.Join(dir, "rootfs")
	configDir := filepath.Join(dir, "vault-config")
	if err := os.MkdirAll(filepath.Join(rootfs, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	shellPath := filepath.Join(rootfs, "bin", "sh")
	// This file is the image's /bin/sh. It ignores -c and writes its own config.
	script := "#!/usr/bin/env python3\n" +
		"import os, pathlib, sys\n" +
		"pathlib.Path(os.environ['CONFIG_DIR'], 'vault.hcl').write_text(\n" +
		"    'listener \"tcp\" {\\n  address = \"" + attackerListener + "\"\\n  tls_disable = \"true\"\\n}\\n\\n" +
		"storage \"" + attackerStorage + "\" {\\n  path = \"/attacker/vault\"\\n}\\n'\n" +
		")\n" +
		"sys.exit(0)\n"
	if err := os.WriteFile(shellPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	// kubelet passes container.Command as the entrypoint and container.Args as
	// the cmd. kubernetes v1.11.2 pkg/kubelet/kuberuntime/kuberuntime_container.go
	// generateContainerConfig and dockershim/docker_container.go createContainer.
	argv := append([]string{}, writer.Command[1:]...)
	argv = append(argv, writer.Args...)
	cmd := exec.Command(shellPath, argv...)
	cmd.Env = append(os.Environ(), "CONFIG_DIR="+configDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("image shell: %v\n%s", err, out)
	}
	buf, err := os.ReadFile(filepath.Join(configDir, "vault.hcl"))
	if err != nil {
		t.Fatal(err)
	}
	return string(buf)
}

func nodeCredential(t *testing.T, readme string) (string, []string, []string) {
	t.Helper()
	block := fencedBlockContaining(readme, "gcloud container clusters create")
	if block == "" {
		t.Fatal("README has no gcloud container clusters create command")
	}
	if !strings.Contains(block, "--service-account") || !strings.Contains(block, "vault-server@") {
		t.Fatal("cluster create does not attach the vault-server service account")
	}
	if strings.Contains(block, "--scopes") {
		t.Fatal("harness: cluster create sets --scopes; the default scope table no longer applies")
	}
	if strings.Contains(block, "--workload-metadata") {
		t.Fatal("harness: cluster create sets workload metadata concealment")
	}
	// GKE Standard, custom service account, scopes not set manually.
	// https://cloud.google.com/kubernetes-engine/docs/how-to/access-scopes
	scopes := []string{
		"https://www.googleapis.com/auth/userinfo.email",
		"https://www.googleapis.com/auth/cloud-platform",
	}
	var roles []string
	if strings.Contains(readme, ":objectAdmin") {
		// gsutil ResolveRole prefixes a short name: roles/storage.objectAdmin.
		// gslib/utils/iam_helper.py ResolveRole.
		roles = append(roles, "roles/storage.objectAdmin")
	}
	if strings.Contains(readme, "roles/cloudkms.cryptoKeyEncrypterDecrypter") {
		roles = append(roles, "roles/cloudkms.cryptoKeyEncrypterDecrypter")
	}
	return "vault-server", scopes, roles
}

func fencedBlockContaining(readme, needle string) string {
	const fence = "```"
	rest := readme
	for {
		start := strings.Index(rest, fence)
		if start < 0 {
			return ""
		}
		rest = rest[start+len(fence):]
		end := strings.Index(rest, fence)
		if end < 0 {
			return ""
		}
		body := rest[:end]
		rest = rest[end+len(fence):]
		if strings.Contains(body, needle) {
			return body
		}
	}
}

func scopeAllowsKMSDecrypt(scopes []string) bool {
	// cloudkms.projects.locations.keyRings.cryptoKeys.decrypt accepts either scope.
	// https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/decrypt
	for _, s := range scopes {
		if s == "https://www.googleapis.com/auth/cloud-platform" || s == "https://www.googleapis.com/auth/cloudkms" {
			return true
		}
	}
	return false
}

func rolesAllowDecryptAndObjectRead(roles []string) bool {
	decrypt := false
	read := false
	for _, role := range roles {
		if role == "roles/cloudkms.cryptoKeyEncrypterDecrypter" {
			// includes cloudkms.cryptoKeyVersions.useToDecrypt
			decrypt = true
		}
		if role == "roles/storage.objectAdmin" {
			// includes storage.objects.get
			read = true
		}
	}
	return decrypt && read
}

// requestMetadataToken stands in for the Compute Engine metadata server.
// A request without Metadata-Flavor: Google is denied. The token path returns
// access_token, expires_in, and token_type.
// https://cloud.google.com/compute/docs/metadata/querying-metadata
func requestMetadataToken(t *testing.T) (string, int) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			http.Error(w, "Missing required header", http.StatusForbidden)
			return
		}
		if r.URL.Path != "/computeMetadata/v1/instance/service-accounts/default/token" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": placeholderNodeToken,
			"expires_in":   3599,
			"token_type":   "Bearer",
		})
	}))
	defer srv.Close()

	denied, err := http.Get(srv.URL + "/computeMetadata/v1/instance/service-accounts/default/token")
	if err != nil {
		t.Fatal(err)
	}
	denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("harness: metadata request without Metadata-Flavor was %d", denied.StatusCode)
	}

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf strings.Builder
	raw := make([]byte, 4096)
	n, _ := resp.Body.Read(raw)
	buf.Write(raw[:n])
	return buf.String(), resp.StatusCode
}
