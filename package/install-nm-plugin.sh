#!/usr/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

echo "Installing NetworkManager SNX Plugin..."

# 1. Install binaries to /usr/libexec
# Assuming the binaries are in the current directory or target/release/debug
# For this script, we'll try to find them in typical build locations or current dir
if [ -f "./target/release/nm-snx-service" ]; then
    SRC_DIR="./target/release"
    # Prefer release unless debug is explicitly requested or release is missing?
    # Actually, the logic below checks for existence.
    # Let's check args for --debug
    if [[ "$*" == *"--debug"* ]]; then
        if [ -f "./target/debug/nm-snx-service" ]; then
            SRC_DIR="./target/debug"
        else
            echo "Debug binaries requested but not found in ./target/debug"
            exit 1
        fi
    fi
elif [ -f "./target/debug/nm-snx-service" ]; then
    SRC_DIR="./target/debug"
elif [ -f "./nm-snx-service" ]; then
    SRC_DIR="."
else
    echo "Error: Binaries not found. Please build the project first."
    exit 1
fi

echo "Installing binaries from $SRC_DIR to /usr/libexec/..."
install -m 755 "$SRC_DIR/nm-snx-service" /usr/libexec/
install -m 755 "$SRC_DIR/nm-snx-auth-dialog" /usr/libexec/

# 2. Install editor plugin library
EDITOR_LIB=""
if [ -f "./apps/nm-snx-editor/builddir/libnm-vpn-plugin-snx.so" ]; then
    EDITOR_LIB="./apps/nm-snx-editor/builddir/libnm-vpn-plugin-snx.so"
elif [ -f "./libnm-vpn-plugin-snx.so" ]; then
    EDITOR_LIB="./libnm-vpn-plugin-snx.so"
fi

if [ -n "$EDITOR_LIB" ]; then
    echo "Installing editor plugin library..."
    # Determine NetworkManager lib directory
    NM_LIBDIR="/usr/lib64/NetworkManager"
    if [ ! -d "$NM_LIBDIR" ]; then
        NM_LIBDIR="/usr/lib/NetworkManager"
    fi
    install -m 755 "$EDITOR_LIB" "$NM_LIBDIR/"
else
    echo "Warning: libnm-vpn-plugin-snx.so not found, skipping editor plugin installation"
fi

# 3. Install NetworkManager VPN plugin definition
echo "Installing VPN plugin definition..."
install -m 644 ./package/nm/snx.name /usr/lib/NetworkManager/VPN/

# 4. Install DBus service file
echo "Installing DBus service file..."
install -m 644 ./package/nm/org.freedesktop.NetworkManager.snx.service /usr/share/dbus-1/system-services/

# 5. Install DBus security configuration
echo "Installing DBus security configuration..."
install -m 644 ./package/nm/nm-snx.conf /etc/dbus-1/system.d/

# 6. Reload NetworkManager to pick up changes
echo "Reloading NetworkManager..."
systemctl reload NetworkManager

echo "Installation of NetworkManager SNX Plugin finished."
