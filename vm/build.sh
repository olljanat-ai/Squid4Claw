#!/bin/sh
# Build Firewall4AI VM disk images (qcow2, vmdk, vhdx)
# Requires: alpine-make-vm-image, qemu-img, Go toolchain
# Must run as root on Alpine Linux (or in CI with appropriate setup).
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$PROJECT_DIR/dist}"
IMAGE_SIZE="${IMAGE_SIZE:-1G}"
ALPINE_BRANCH="${ALPINE_BRANCH:-latest-stable}"
VERSION="${VERSION:-dev}"

# Packages needed in the VM
PACKAGES="iptables dnsmasq e2fsprogs-extra"

echo "=== Firewall4AI VM Image Builder ==="
echo "Version: $VERSION"
echo "Output:  $OUTPUT_DIR"
echo ""

# ============================================================
# Build the firewall4ai binary
# ============================================================
echo "--- Building firewall4ai binary ---"
BINARY="$SCRIPT_DIR/firewall4ai"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags "-s -w -X main.Version=${VERSION}" \
    -o "$BINARY" \
    "$PROJECT_DIR/cmd/firewall4ai/"
echo "Binary built: $BINARY"

# ============================================================
# Build the qcow2 image
# ============================================================
mkdir -p "$OUTPUT_DIR"
QCOW2="$OUTPUT_DIR/firewall4ai-${VERSION}.qcow2"

echo "--- Building qcow2 image ---"
alpine-make-vm-image \
    --image-format qcow2 \
    --image-size "$IMAGE_SIZE" \
    --branch "$ALPINE_BRANCH" \
    --packages "$PACKAGES" \
    --fs-skel-dir "$SCRIPT_DIR/rootfs" \
    --serial-console \
    --script-chroot \
    -- \
    "$QCOW2" \
    "$SCRIPT_DIR/configure.sh"

echo "Built: $QCOW2"

# ============================================================
# Convert to VMware (vmdk)
# ============================================================
VMDK="$OUTPUT_DIR/firewall4ai-${VERSION}.vmdk"
echo "--- Converting to vmdk ---"
qemu-img convert -f qcow2 -O vmdk \
    -o adapter_type=lsilogic,subformat=streamOptimized \
    "$QCOW2" "$VMDK"
echo "Built: $VMDK"

# ============================================================
# Convert to Hyper-V (vhdx)
# ============================================================
VHDX="$OUTPUT_DIR/firewall4ai-${VERSION}.vhdx"
echo "--- Converting to vhdx ---"
qemu-img convert -f qcow2 -O vhdx \
    -o subformat=dynamic \
    "$QCOW2" "$VHDX"
echo "Built: $VHDX"

# ============================================================
# Cleanup
# ============================================================
rm -f "$BINARY"

echo ""
echo "=== Build complete ==="
ls -lh "$OUTPUT_DIR"/firewall4ai-${VERSION}.*
