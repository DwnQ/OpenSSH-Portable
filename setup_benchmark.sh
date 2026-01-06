#!/bin/bash
set -e

echo "=== Docker Benchmark Setup ==="

# 1. Generate host keys if missing
echo "[1/6] Generating host keys..."
/opt/customsshServer/bin/ssh-keygen -A 2>/dev/null || true

# 2. Create sshd_config
echo "[2/6] Creating sshd_config..."
cat > /opt/customsshServer/etc/sshd_config << 'EOF'
Port 2222
ListenAddress 127.0.0.1
HostKey /opt/customsshServer/etc/ssh_host_ed25519_key
HostKey /opt/customsshServer/etc/ssh_host_rsa_key
PermitRootLogin yes
AuthorizedKeysFile .ssh/authorized_keys
PidFile /tmp/customsshd.pid
PubkeyAuthentication yes
PasswordAuthentication no
LogLevel DEBUG3
PubkeyAcceptedAlgorithms +pqc-falcon512
HostKeyAlgorithms +pqc-falcon512
EOF

# 3. Generate user keys
echo "[3/6] Generating client keys..."
if [ ! -f ~/.ssh/id_ed25519 ]; then
    /opt/customsshClient/bin/ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""
fi
if [ ! -f ~/.ssh/id_falcon512 ]; then
    /opt/customsshClient/bin/ssh-keygen -t falcon512 -f ~/.ssh/id_falcon512 -N ""
fi

# 4. Setup authorized_keys
echo "[4/6] Setting up authorized_keys..."
cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys 2>/dev/null || true
cat ~/.ssh/id_falcon512.pub >> ~/.ssh/authorized_keys 2>/dev/null || true
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys

# 5. Start sshd
echo "[5/6] Starting sshd..."
pkill sshd 2>/dev/null || true
/opt/customsshServer/sbin/sshd

# 6. Test connection
echo "[6/6] Testing connection..."
sleep 1
/opt/customsshClient/bin/ssh -p 2222 -o StrictHostKeyChecking=no -i ~/.ssh/id_ed25519 $USER@127.0.0.1 "echo 'SSH connection successful!'"

echo ""
echo "=== Setup Complete ==="
echo "Run benchmarks with: cd /src && ./benchmark_subverted.sh"
