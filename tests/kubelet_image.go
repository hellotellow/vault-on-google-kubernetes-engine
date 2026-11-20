package pin

// Image pull decisions below are the Kubernetes 1.11.2 kubelet rules this
// deployment's cluster version (README: 1.11.2-gke.9) uses. They are copied
// from:
//
//   - pkg/util/parsers/parsers.go ParseImageName (v1.11.2)
//   - pkg/apis/core/v1/defaults.go SetDefaults_Container (v1.11.2)
//   - pkg/kubelet/images/image_manager.go shouldPullImage and applyDefaultImageTag (v1.11.2)
//
// The reference grammar is github.com/docker/distribution/reference at
// edc3ab29cdff8694dd6feb85cfeb4b5f1b38ed9c, the revision Kubernetes 1.11.2 vendors.

import (
	"fmt"

	"github.com/hellotellow/vault-on-google-kubernetes-engine/tests/reference"
)

const defaultImageTag = "latest"

// parseImageName matches parsers.ParseImageName.
func parseImageName(image string) (repo, tag, digest string, err error) {
	named, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return "", "", "", fmt.Errorf("couldn't parse image name: %v", err)
	}
	repo = named.Name()
	if tagged, ok := named.(reference.Tagged); ok {
		tag = tagged.Tag()
	}
	if digested, ok := named.(reference.Digested); ok {
		digest = digested.Digest().String()
	}
	if len(tag) == 0 && len(digest) == 0 {
		tag = defaultImageTag
	}
	return repo, tag, digest, nil
}

// applyDefaultImageTag matches images.applyDefaultImageTag. The string it
// returns is what EnsureImageExists hands to the runtime puller.
func applyDefaultImageTag(image string) (string, error) {
	named, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return "", fmt.Errorf("couldn't parse image reference %q: %v", image, err)
	}
	_, isTagged := named.(reference.Tagged)
	_, isDigested := named.(reference.Digested)
	if !isTagged && !isDigested {
		image = image + ":" + defaultImageTag
	}
	return image, nil
}

// effectivePullPolicy matches SetDefaults_Container when the pod spec leaves
// imagePullPolicy empty.
func effectivePullPolicy(image, policy string) (string, error) {
	if policy != "" {
		return policy, nil
	}
	_, tag, _, err := parseImageName(image)
	if err != nil {
		return "", err
	}
	if tag == defaultImageTag {
		return "Always", nil
	}
	return "IfNotPresent", nil
}

// shouldPullImage matches images.shouldPullImage.
func shouldPullImage(policy string, imagePresent bool) bool {
	if policy == "Never" {
		return false
	}
	if policy == "Always" || (policy == "IfNotPresent" && !imagePresent) {
		return true
	}
	return false
}

// pullRefIsDigest reports whether the reference the kubelet would pull is
// content-addressed. A tag, including the default "latest", is not.
func pullRefIsDigest(image string) (bool, string, error) {
	pulled, err := applyDefaultImageTag(image)
	if err != nil {
		return false, "", err
	}
	_, _, digest, err := parseImageName(pulled)
	if err != nil {
		return false, pulled, err
	}
	return digest != "", pulled, nil
}
