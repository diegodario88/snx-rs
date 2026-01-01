#!/bin/bash
#
# Build script for NetworkManager SNX Plugin
#
# Build Dependencies (Fedora/RHEL):
#   sudo dnf install cargo rust gcc meson ninja-build \
#       gtk4-devel libadwaita-devel libnm-devel \
#       libsecret-devel glib2-devel
#
# Build Dependencies (Debian/Ubuntu):
#   sudo apt install cargo rustc gcc meson ninja-build \
#       libgtk-4-dev libadwaita-1-dev libnm-dev \
#       libsecret-1-dev libglib2.0-dev
#

set -e

basedir="$(dirname $(readlink -f $0))/.."
cd "$basedir"

echo "=== Building NetworkManager SNX Plugin ==="
echo ""

# Check for required tools
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo "ERROR: $1 is required but not installed."
        exit 1
    fi
}

check_tool cargo
check_tool meson
check_tool ninja

# 1. Build Rust binaries
echo "[1/2] Building Rust components..."
cargo build --release -p nm-snx-service -p nm-snx-auth-dialog

# 2. Build C editor plugin
echo "[2/2] Building editor plugin (C)..."
cd "$basedir/apps/nm-snx-editor"
if [ -d builddir ]; then
    rm -rf builddir
fi
meson setup builddir
meson compile -C builddir

cd "$basedir"

echo ""
echo "=== Build complete ==="
echo ""
echo "Binaries created:"
echo "  - target/release/nm-snx-service"
echo "  - target/release/nm-snx-auth-dialog"
echo "  - apps/nm-snx-editor/builddir/libnm-vpn-plugin-snx.so"
echo ""
echo "Run ./package/package-nm-plugin.sh to create the RPM package."
