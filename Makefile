install-deps:
	@go install github.com/vektra/mockery/v2@v2.53.0
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin latest

install-tools:
	@go install golang.org/x/tools/gopls@latest
	@go install github.com/cweill/gotests/gotests@latest
	@go install github.com/fatih/gomodifytags@latest
	@go install github.com/josharian/impl@latest
	@go install github.com/haya14busa/goplay/cmd/goplay@latest
	@go install github.com/go-delve/delve/cmd/dlv@latest
	@go install honnef.co/go/tools/cmd/staticcheck@latest

mock:
	@mockery

lint:
	@golangci-lint run