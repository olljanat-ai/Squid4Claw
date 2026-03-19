#!/bin/sh
# Configure script for alpine-make-vm-image
# This runs inside the VM image chroot during build.
set -eu

# ============================================================
# Basic system setup
# ============================================================

# Set timezone
ln -sf /usr/share/zoneinfo/UTC /etc/localtime

# Set hostname
echo "firewall4ai" > /etc/hostname
echo "127.0.0.1 firewall4ai firewall4ai.localdomain" >> /etc/hosts

# Set root password (change on first login)
echo "root:firewall4ai" | chpasswd

# ============================================================
# Copy the firewall4ai binary
# ============================================================
cp /mnt/firewall4ai /usr/bin/firewall4ai
chmod 755 /usr/bin/firewall4ai

# ============================================================
# Enable services
# ============================================================
rc-update add networking boot
rc-update add dnsmasq default
rc-update add local default
rc-update add firewall4ai default
rc-update add acpid default

# ============================================================
# Enable IP forwarding at boot
# ============================================================
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf

# ============================================================
# Configure DNS resolver for the host itself
# ============================================================
cat > /etc/resolv.conf <<EOF
nameserver 1.1.1.1
nameserver 1.0.0.1
EOF

# ============================================================
# Create data directory
# ============================================================
mkdir -p /var/lib/firewall4ai

# ============================================================
# Auto login to console
# ============================================================
sed -i -e 's/tty1::respawn:\/sbin\/getty 38400 tty1/tty1::respawn:\/sbin\/agetty --autologin root tty1 linux/' /etc/inittab

echo "Firewall4AI VM configuration complete"

