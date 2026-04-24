BINARY_NAME=shadowgraph
GO=go
VERSION=0.2.0
LDFLAGS=-ldflags="-s -w -X main.Version=$(VERSION)"

.PHONY: build build-all clean run-scan run-ui tidy test

# Mevcut platform için build
build:
ifeq ($(OS),Windows_NT)
	$(GO) build $(LDFLAGS) -o $(BINARY_NAME).exe .
else
	$(GO) build $(LDFLAGS) -o $(BINARY_NAME) .
endif

# Cross-platform build (Windows, Linux, macOS)
build-all:
	GOOS=windows GOARCH=amd64 $(GO) build $(LDFLAGS) -o dist/$(BINARY_NAME)-windows-amd64.exe .
	GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64 $(GO) build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-arm64 .
	GOOS=darwin GOARCH=amd64 $(GO) build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 $(GO) build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-arm64 .
	@echo "Build tamamlandi: dist/"

clean:
ifeq ($(OS),Windows_NT)
	if exist $(BINARY_NAME).exe del /Q $(BINARY_NAME).exe
	if exist dist rmdir /S /Q dist
else
	rm -f $(BINARY_NAME)
	rm -rf dist/
endif

tidy:
	$(GO) mod tidy

run-scan:
	$(GO) run . scan -t $(TARGET)

run-ui:
	$(GO) run . ui

test:
	$(GO) test ./...
