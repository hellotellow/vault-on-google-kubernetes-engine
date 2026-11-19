module github.com/hellotellow/vault-on-google-kubernetes-engine/tests/supplychain

go 1.22

require (
	github.com/docker/distribution v0.0.0
	github.com/hashicorp/hcl v1.0.1-0.20180906183839-65a6292f0157
	gopkg.in/yaml.v3 v3.0.1
)

require github.com/opencontainers/go-digest v0.0.0-20170106003457-a6d0ee40d420 // indirect

replace github.com/docker/distribution => ./internal/distribution
