.PHONY: build test golden prove vet dist

# Raise this for every release. The installer and `fenzi update` read
# latest.txt, and a release that keeps the old number is never offered.
VERSION ?= 0.1.35

build:
	go build -trimpath -o bin/fenzi ./cli

test:
	go test ./...

vet:
	go vet ./...

# Rewrite compiler golden files after an intended change. Review the diff.
golden:
	go test ./compiler -update

# Run the upstream prover on every golden policy against its boundary.
# Needs openshell-prover; no gateway. Like run, it proves the files without
# allow_encoded_slash, which prover 0.1.2 and 0.1.4 cannot read (Policy.ForProver).
prove:
	@command -v openshell-prover >/dev/null || { echo "openshell-prover is not installed"; exit 1; }
	@tmp=$$(mktemp -d); fail=0; for p in compiler/testdata/golden/*.policy.yaml; do \
		b=$${p%.policy.yaml}.boundary.yaml; \
		grep -v 'allow_encoded_slash: true' "$$p" > "$$tmp/policy.yaml"; \
		grep -v 'allow_encoded_slash: true' "$$b" > "$$tmp/boundary.yaml"; \
		echo "== $$p"; \
		openshell-prover check "$$tmp/policy.yaml" --boundary "$$tmp/boundary.yaml" --output json || fail=1; \
	done; rm -rf "$$tmp"; exit $$fail

# Binaries the install script downloads. Checksums are sha256, two spaces, then the file name.
dist:
	rm -rf dist
	mkdir -p dist
	@for pair in darwin/arm64 darwin/amd64 linux/arm64 linux/amd64; do \
		os=$${pair%/*}; arch=$${pair#*/}; \
		out=dist/fenzi-$(VERSION)-$$os-$$arch; \
		echo "== $$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "-X main.Version=$(VERSION)" -o $$out ./cli; \
	done
	cd dist && shasum -a 256 fenzi-$(VERSION)-* | awk '{ print $$1 "  " $$2 }' > fenzi-$(VERSION)-sha256.txt
	echo $(VERSION) > dist/latest.txt
