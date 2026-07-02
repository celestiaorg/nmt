## lint: Run all linters; golangci-lint, markdownlint.
lint:
	@echo "--> Running golangci-lint"
	@golangci-lint run
	@echo "--> Running markdownlint"
	@markdownlint --config .markdownlint.yaml '**/*.md'
.PHONY: lint

## markdown-link-check: Check all markdown links.
markdown-link-check:
	@echo "--> Running markdown-link-check"
	@find . -name \*.md -print0 | xargs -0 -n1 markdown-link-check
.PHONY: markdown-link-check

## proto-gen: Generate Go code from protobuf definition files. Requires protoc.
proto-gen:
	@echo "--> Installing protoc-gen-gogofaster (version pinned by go.mod)"
	@go install github.com/gogo/protobuf/protoc-gen-gogofaster
	@echo "--> Generating Protobuf files"
	@gobin="$$(go env GOBIN)"; [ -n "$$gobin" ] || gobin="$$(go env GOPATH)/bin"; \
	protoc --plugin=protoc-gen-gogofaster="$$gobin/protoc-gen-gogofaster" --gogofaster_out=paths=source_relative:. pb/proof.proto
.PHONY: proto-gen
