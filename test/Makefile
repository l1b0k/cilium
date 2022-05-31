# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../Makefile.defs

PROVISION ?= true
# If you set provision to false the test will run without bootstrapping the
# cluster again.
HOLD_ENVIRONMENT ?= true

TEST_ARTIFACTS = ./tmp.yaml ./*_service_manifest.json ./*_manifest.yaml
TEST_ARTIFACTS += ./*_policy.json ./k8s-*.xml ./runtime.xml ./test_results
TEST_ARTIFACTS += ./test.test

NETNEXT ?= false
KUBEPROXY ?= 1
NO_CILIUM_ON_NODES ?= ""

CNI_VERSION="v1.1.1"
CNI_TARBALL="${CNI_VERSION}/cni-plugins-linux-amd64-${CNI_VERSION}.tgz"
CNI_URL="https://github.com/containernetworking/plugins/releases/download/${CNI_TARBALL}"

GINKGO = $(QUIET) ginkgo

REGISTRY_CREDENTIALS ?= "${DOCKER_LOGIN}:${DOCKER_PASSWORD}"

.PHONY = all build test run k8s-test k8s-kind nightly clean run_bpf_tests

all: build

build:
	@$(ECHO_GINKGO)$@
	$(GINKGO) build -tags=integration_tests
	$(QUIET)$(MAKE) -C bpf/

test: run k8s-test

run:
	KERNEL=net-next ginkgo --focus "Runtime" --tags integration_tests -v -- --cilium.provision=$(PROVISION) --cilium.registryCredentials=$(REGISTRY_CREDENTIALS)

k8s-test:
	ginkgo --focus "K8s" --tags integration_tests -v -- --cilium.provision=$(PROVISION) --cilium.registryCredentials=$(REGISTRY_CREDENTIALS)

# Match kind-image target in parent directory
k8s-kind: export DOCKER_REGISTRY=localhost:5000
k8s-kind:
	@if [ -z $(FOCUS) ]; then \
		>&2 echo "usage: FOCUS=K8sFoo make k8s-kind"; \
		exit 1; \
	fi

	curl -sSL --retry 5 --output /tmp/cni.tgz "${CNI_URL}" \
	&& mkdir -p /tmp/cni \
	&& tar -C /tmp/cni -xzf /tmp/cni.tgz \
	&& rm -f /tmp/cni.tgz \
	&& kind get nodes | xargs -n1 -I {} bash -c "docker cp /tmp/cni/ipvlan {}:/opt/cni/bin" \
	&& rm -rf /tmp/cni

	@CNI_INTEGRATION=kind \
		K8S_VERSION="$$(kubectl version -o json | jq -r '.serverVersion | "\(.major).\(.minor)"')" \
		NETNEXT="$(NETNEXT)" \
		KUBEPROXY="$(KUBEPROXY)" \
		NO_CILIUM_ON_NODES="$(NO_CILIUM_ON_NODES)" \
		ginkgo --focus "$(FOCUS)" --tags integration_tests -v -- \
			-cilium.testScope=k8s \
			-cilium.provision=false \
			-cilium.kubeconfig=$$(echo ~/.kube/config) \
			-cilium.passCLIEnvironment=true \
			-cilium.image="$(DOCKER_REGISTRY)/cilium/cilium-dev" \
			-cilium.tag="local" \
			-cilium.operator-image="quay.io/cilium/operator" \
			-cilium.operator-suffix="-ci" \
			-cilium.holdEnvironment=$(HOLD_ENVIRONMENT)

nightly:
	ginkgo --focus "Nightly" -v --tags integration_tests -- --cilium.provision=$(PROVISION) --cilium.registryCredentials=$(REGISTRY_CREDENTIALS)

clean:
	@$(ECHO_CLEAN)
	-$(QUIET) rm -rf $(TEST_ARTIFACTS)
	-$(QUIET) rm -f .vagrant/*.box

BPF_TEST_FLAGS:=
ifneq ($(V),0)
    BPF_TEST_FLAGS += -test.v
endif

run_bpf_tests:
	$(QUIET)$(MAKE) -C ../bpf/tests all
	$(QUIET)$(GO) test bpf_tests/*.go -exec sudo -bpf-test-path $(ROOT_DIR)/bpf/tests $(BPF_TEST_FLAGS)
