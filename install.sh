#!/bin/sh
set -e

REPO="falcga/pipg"
BINARY_NAME="pipg"

echo "Detecting system architecture..."

OS_RAW=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS_RAW" in
    linux*)  OS="linux" ;;
    darwin*) OS="darwin" ;;
    *)
        echo "Error: Unsupported operating system: $OS_RAW"
        exit 1
        ;;
esac

ARCH_RAW=$(uname -m)
case "$ARCH_RAW" in
    x86_64|amd64) ARCH="amd64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *)
        echo "Error: Unsupported architecture: $ARCH_RAW"
        exit 1
        ;;
esac

EXPECTED_BINARY="pipg-${OS}-${ARCH}"
echo "Identified target: ${OS}/${ARCH} (${EXPECTED_BINARY})"

echo "Fetching latest release information..."
RELEASE_JSON=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest")

DOWNLOAD_URL=$(echo "$RELEASE_JSON" | grep -o "https://github.com/${REPO}/releases/download/[^/']*/${EXPECTED_BINARY}" | head -n 1)

if [ -z "$DOWNLOAD_URL" ]; then
    echo "Error: Could not find binary '${EXPECTED_BINARY}' in the latest release."
    exit 1
fi

TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

echo "Downloading ${EXPECTED_BINARY}..."
curl -L -o "$BINARY_NAME" "$DOWNLOAD_URL"
chmod +x "$BINARY_NAME"

INSTALL_DIR="/usr/local/bin"
echo "Installing to ${INSTALL_DIR}/${BINARY_NAME}..."

if [ -w "$INSTALL_DIR" ]; then
    mv "$BINARY_NAME" "${INSTALL_DIR}/${BINARY_NAME}"
else
    echo "Write permissions required for ${INSTALL_DIR}. Requesting root access..."
    sudo mv "$BINARY_NAME" "${INSTALL_DIR}/${BINARY_NAME}"
fi

cd - > /dev/null
rm -rf "$TMP_DIR"

echo "Successfully installed ${BINARY_NAME}! Run '${BINARY_NAME}' to get started."
