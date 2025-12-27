#!/bin/bash

# 测试脚本 - 用于本地测试 geosite 构建流程
# 不会实际运行，仅检查依赖和代码语法

set -e

echo "=== Testing Geosite Build Process ==="
echo ""

# 检查 Go 是否安装
echo "1. Checking Go installation..."
if command -v go &> /dev/null; then
    go version
    echo "✓ Go is installed"
else
    echo "✗ Go is not installed"
    echo "  Please install Go 1.22 or later"
    exit 1
fi
echo ""

# 检查 Go 版本
echo "2. Checking Go version..."
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
REQUIRED_VERSION="1.22"
if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$GO_VERSION" | sort -V | head -n1)" = "$REQUIRED_VERSION" ]; then
    echo "✓ Go version is $GO_VERSION (>= $REQUIRED_VERSION)"
else
    echo "✗ Go version is $GO_VERSION (< $REQUIRED_VERSION)"
    echo "  Please upgrade Go to 1.22 or later"
    exit 1
fi
echo ""

# 检查 build_geosite.go 文件
echo "3. Checking build_geosite.go..."
if [ -f "build_geosite.go" ]; then
    echo "✓ build_geosite.go exists"
else
    echo "✗ build_geosite.go not found"
    exit 1
fi
echo ""

# 检查 go.mod 文件
echo "4. Checking go.mod..."
if [ -f "go.mod" ]; then
    echo "✓ go.mod exists"
else
    echo "✗ go.mod not found"
    exit 1
fi
echo ""

# 下载依赖
echo "5. Downloading Go dependencies..."
go mod download
echo "✓ Dependencies downloaded"
echo ""

# 检查语法
echo "6. Checking Go syntax..."
go vet build_geosite.go
echo "✓ No syntax errors"
echo ""

# 尝试编译（不运行）
echo "7. Testing compilation..."
go build -o /tmp/build_geosite_test build_geosite.go
rm -f /tmp/build_geosite_test
echo "✓ Compilation successful"
echo ""

echo "=== All tests passed! ==="
echo ""
echo "To run the actual build process, use:"
echo "  go run build_geosite.go"
echo ""
echo "Or run it in GitHub Actions"

