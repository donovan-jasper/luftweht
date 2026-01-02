.PHONY: all clean frontend scanner viewer releases release-darwin-arm64 release-linux-amd64 release-linux-arm64

# Default target
all: frontend scanner viewer

# Build frontend
frontend:
	cd viewer/frontend && npm install && npm run build

# Build scanner for current platform
scanner: frontend
	go build -o luftweht ./cmd/scanner

# Build viewer for current platform
viewer: frontend
	go build -o luftweht-viewer ./viewer

# Clean build artifacts
clean:
	rm -f luftweht luftweht-viewer
	rm -rf releases/
	rm -rf viewer/frontend/dist

# Build all releases
releases: release-darwin-arm64 release-linux-amd64 release-linux-arm64

# Mac ARM64 (requires building on Mac ARM)
release-darwin-arm64: frontend
	@mkdir -p releases
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build -o releases/luftweht-darwin-arm64 ./cmd/scanner
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build -o releases/luftweht-viewer-darwin-arm64 ./viewer

# Linux AMD64 (uses Docker for cross-compilation)
release-linux-amd64: frontend
	@mkdir -p releases
	docker run --rm --platform linux/amd64 \
		-v "$$(pwd)":/app -w /app \
		golang:1.23 \
		bash -c "CGO_ENABLED=1 go build -o releases/luftweht-linux-amd64 ./cmd/scanner && \
		         CGO_ENABLED=1 go build -o releases/luftweht-viewer-linux-amd64 ./viewer"

# Linux ARM64 (uses Docker for cross-compilation)
release-linux-arm64: frontend
	@mkdir -p releases
	docker run --rm --platform linux/arm64 \
		-v "$$(pwd)":/app -w /app \
		golang:1.23 \
		bash -c "CGO_ENABLED=1 go build -o releases/luftweht-linux-arm64 ./cmd/scanner && \
		         CGO_ENABLED=1 go build -o releases/luftweht-viewer-linux-arm64 ./viewer"

# Package releases into archives
package: releases
	cd releases && tar -czf luftweht-darwin-arm64.tar.gz luftweht-darwin-arm64 luftweht-viewer-darwin-arm64
	cd releases && tar -czf luftweht-linux-amd64.tar.gz luftweht-linux-amd64 luftweht-viewer-linux-amd64
	cd releases && tar -czf luftweht-linux-arm64.tar.gz luftweht-linux-arm64 luftweht-viewer-linux-arm64
