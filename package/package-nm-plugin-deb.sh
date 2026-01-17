#!/bin/bash
#
# Package script for NetworkManager SNX Plugin (.deb)
#
# This script creates a Debian package for the NetworkManager SNX VPN plugin.
# Run ./package/build-nm-plugin.sh first to build the binaries.
#

set -e

basedir="$(dirname $(readlink -f $0))/.."
target="$basedir/target"

# Get version from environment variable, git tag, or Cargo.toml
if [ -n "$TAG_NAME" ]; then
    version="$TAG_NAME"
elif git -C "$basedir" describe --tags --exact-match HEAD >/dev/null 2>&1; then
    version="$(git -C "$basedir" describe --tags --exact-match HEAD)"
else
    # Fallback to Cargo.toml version
    version="v$(grep '^version' "$basedir/Cargo.toml" | head -1 | sed 's/.*"\(.*\)"/\1/')"
fi

deb_version="${version#v}"  # Remove 'v' prefix
arch="$(uname -m)"

case $arch in
    aarch64)
        deb_arch=arm64
        lib_arch="aarch64-linux-gnu"
        ;;
    x86_64)
        deb_arch=amd64
        lib_arch="x86_64-linux-gnu"
        ;;
    *)
        deb_arch=$arch
        lib_arch="$arch-linux-gnu"
        ;;
esac

echo "=== Packaging NetworkManager SNX Plugin (.deb) ==="
echo "Version: $deb_version"
echo "Architecture: $deb_arch"
echo ""

# Check that binaries exist
check_binary() {
    if [ ! -f "$1" ]; then
        echo "ERROR: $1 not found. Run ./package/build-nm-plugin.sh first."
        exit 1
    fi
}

check_binary "$target/release/nm-snx-service"
check_binary "$target/release/nm-snx-auth-dialog"
check_binary "$basedir/apps/nm-snx-editor/builddir/libnm-vpn-plugin-snx.so"

# Create package structure
name="networkmanager-snx-${version}-linux-$arch"
tmpdir="$(mktemp -d)"
pkgdir="$tmpdir/pkg"
debian="$pkgdir/DEBIAN"

echo "[1/4] Creating package structure..."

mkdir -p "$debian"
mkdir -p "$pkgdir/usr/lib/NetworkManager"
mkdir -p "$pkgdir/usr/lib/NetworkManager/VPN"
mkdir -p "$pkgdir/usr/lib/$lib_arch/NetworkManager"
mkdir -p "$pkgdir/etc/dbus-1/system.d"
mkdir -p "$pkgdir/usr/share/dbus-1/system-services"

# Calculate installed size (in KB)
size_service=$(stat -c%s "$target/release/nm-snx-service")
size_dialog=$(stat -c%s "$target/release/nm-snx-auth-dialog")
size_plugin=$(stat -c%s "$basedir/apps/nm-snx-editor/builddir/libnm-vpn-plugin-snx.so")
installed_size=$(( (size_service + size_dialog + size_plugin) / 1024 ))

echo "[2/4] Installing files..."

# Install binaries
install -m 755 "$target/release/nm-snx-service" "$pkgdir/usr/lib/NetworkManager/"
install -m 755 "$target/release/nm-snx-auth-dialog" "$pkgdir/usr/lib/NetworkManager/"
install -m 755 "$basedir/apps/nm-snx-editor/builddir/libnm-vpn-plugin-snx.so" "$pkgdir/usr/lib/$lib_arch/NetworkManager/"

# Install configuration files
install -m 644 "$basedir/package/nm/snx.name.debian" "$pkgdir/usr/lib/NetworkManager/VPN/snx.name"
install -m 644 "$basedir/package/nm/nm-snx.conf" "$pkgdir/etc/dbus-1/system.d/"
install -m 644 "$basedir/package/nm/org.freedesktop.NetworkManager.snx.service.debian" "$pkgdir/usr/share/dbus-1/system-services/org.freedesktop.NetworkManager.snx.service"

echo "[3/4] Creating control files..."

# Create control file
sed "s/{{version}}/$deb_version/;s/{{arch}}/$deb_arch/;s/{{size}}/$installed_size/" \
    "$basedir/package/debian/nm-plugin.control.in" > "$debian/control"

# Install maintainer scripts
install -m 755 "$basedir/package/debian/nm-plugin.postinst" "$debian/postinst"
install -m 755 "$basedir/package/debian/nm-plugin.postrm" "$debian/postrm"

echo "[4/4] Building .deb package..."

# Build the package
if ! fakeroot dpkg-deb --build "$pkgdir" "$target/$name.deb"; then
    echo "ERROR: Failed to build .deb package"
    rm -rf "$tmpdir"
    exit 1
fi

# Cleanup
rm -rf "$tmpdir"

echo ""
echo "=== Package created successfully ==="
echo "  $target/$name.deb"
echo ""
