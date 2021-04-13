all: test

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

all: lint test

# Run tests
native-test: generate manifests
	go test ./pkg/... -coverprofile cover.out

# Docker internal test
docker-internal-test:
	make native-test
# The remote driver has some unimplemented functions
# which result in a panic during testing.
#	./tests/test_remote_driver.sh

# Hook to run docker tests
test: generate
	docker build . -t constraint-test && docker run -t constraint-test

# Install CRDs into a cluster
install: manifests
	kubectl apply -f config/crds

# Generate manifests e.g. CRD, RBAC etc.
manifests: controller-gen
	$(CONTROLLER_GEN) \
		crd \
		rbac:roleName=manager-role webhook \
		paths="./..." \
		output:crd:artifacts:config=config/crd/bases \
		object:headerFile=./hack/boilerplate.go.txt

lint:
	golangci-lint -v run ./... --timeout 5m

# Generate code
generate:
	./hack/generate.sh

# find or download controller-gen
# download controller-gen if necessary
controller-gen:
ifeq (, $(shell which controller-gen))
	@{ \
	set -e ;\
	CONTROLLER_GEN_TMP_DIR=$$(mktemp -d) ;\
	cd $$CONTROLLER_GEN_TMP_DIR ;\
	go mod init tmp ;\
	go get sigs.k8s.io/controller-tools/cmd/controller-gen@v0.5.0 ;\
	rm -rf $$CONTROLLER_GEN_TMP_DIR ;\
	}
CONTROLLER_GEN=$(GOBIN)/controller-gen
else
CONTROLLER_GEN=$(shell which controller-gen)
endif
