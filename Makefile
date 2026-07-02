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
	@echo "--> Installing protoc-gen-gogofaster"
	@go install github.com/gogo/protobuf/protoc-gen-gogofaster
	@echo "--> Generating Protobuf files"
	@PATH="$$(go env GOPATH)/bin:$$PATH" protoc --gogofaster_out=paths=source_relative:. pb/proof.proto
.PHONY: proto-gen
