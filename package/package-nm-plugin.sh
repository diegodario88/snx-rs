#!/bin/bash
#
# Package script for NetworkManager-snx RPM
#
# Prerequisites:
#   1. Run ./package/build-nm-plugin.sh first
#   2. Install rpmbuild: sudo dnf install rpm-build
#

set -e

basedir="$(dirname $(readlink -f $0))/.."
cd "$basedir"

target="$basedir/target"

# Try to get version from git tag, fallback to Cargo.toml
version="$(git describe --tags 2>/dev/null | sed 's/^v//' || true)"
if [ -z "$version" ]; then
    # Extract version from Cargo.toml
    version="$(grep -m1 '^version = ' "$basedir/Cargo.toml" | sed 's/version = "\(.*\)"/\1/')"
fi
if [ -z "$version" ]; then
    version="0.0.0"
fi

rpm_version="$(echo $version | sed 's/-/~/g')"
arch="x86_64"

echo "=== Packaging NetworkManager-snx $version ==="
echo ""

# Verify binaries exist
check_file() {
    if [ ! -f "$1" ]; then
        echo "ERROR: $1 not found."
        echo "Please run ./package/build-nm-plugin.sh first."
        exit 1
    fi
}

check_file "$target/release/nm-snx-service"
check_file "$target/release/nm-snx-auth-dialog"
check_file "$basedir/apps/nm-snx-editor/builddir/libnm-vpn-plugin-snx.so"

# Check for rpmbuild
if ! command -v rpmbuild &> /dev/null; then
    echo "ERROR: rpmbuild is required. Install with: sudo dnf install rpm-build"
    exit 1
fi

# Create temp directory structure
tmpdir="$(mktemp -d)"
trap "rm -rf $tmpdir" EXIT

rpm="$tmpdir/rpm"
stagedir="$tmpdir/stage"

echo "[1/4] Creating directory structure..."
mkdir -p "$rpm"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
mkdir -p "$stagedir/usr/libexec"
mkdir -p "$stagedir/usr/lib64/NetworkManager"
mkdir -p "$stagedir/usr/lib/NetworkManager/VPN"
mkdir -p "$stagedir/usr/share/dbus-1/system-services"
mkdir -p "$stagedir/etc/dbus-1/system.d"

# Copy binaries
echo "[2/4] Copying files..."
install -m 755 "$target/release/nm-snx-service" "$stagedir/usr/libexec/"
install -m 755 "$target/release/nm-snx-auth-dialog" "$stagedir/usr/libexec/"
install -m 755 "$basedir/apps/nm-snx-editor/builddir/libnm-vpn-plugin-snx.so" \
    "$stagedir/usr/lib64/NetworkManager/"

# Copy config files
install -m 644 "$basedir/package/nm/snx.name" "$stagedir/usr/lib/NetworkManager/VPN/"
install -m 644 "$basedir/package/nm/org.freedesktop.NetworkManager.snx.service" \
    "$stagedir/usr/share/dbus-1/system-services/"
install -m 644 "$basedir/package/nm/nm-snx.conf" "$stagedir/etc/dbus-1/system.d/"

# Create tarball for rpmbuild
tar -cf "$rpm/SOURCES/files.tar" -C "$stagedir" .

# Generate spec file
echo "[3/4] Generating spec file..."
sed "s/{{version}}/$rpm_version/" \
    "$basedir/package/rpm/nm-plugin.spec.in" > "$rpm/SPECS/nm-plugin.spec"

# Build RPM
echo "[4/4] Building RPM..."
rpmbuild --define "_topdir $rpm" \
         --quiet \
         -bb "$rpm/SPECS/nm-plugin.spec"

# Copy result
output_rpm=$(ls "$rpm/RPMS/$arch"/*.rpm 2>/dev/null | head -1)
if [ -n "$output_rpm" ]; then
    output_name="NetworkManager-snx-${version}.${arch}.rpm"
    cp "$output_rpm" "$target/$output_name"
    echo ""
    echo "=== Package created successfully ==="
    echo ""
    echo "Output: $target/$output_name"
    echo ""
    echo "Install with:"
    echo "  sudo rpm -i $target/$output_name"
    echo ""
    echo "Or with dnf:"
    echo "  sudo dnf install $target/$output_name"
else
    echo "ERROR: RPM build failed"
    exit 1
fi
