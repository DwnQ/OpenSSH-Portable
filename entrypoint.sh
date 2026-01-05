#!/bin/bash
set -e

# Define paths
CLIENT_BASE="/opt/customsshClient"
SERVER_BASE="/opt/customsshServer"
SERVER_ETC="$SERVER_BASE/etc"
SERVER_BIN="$SERVER_BASE/sbin/sshd"
CLIENT_BIN="$CLIENT_BASE/bin/ssh"
KEYGEN="$CLIENT_BASE/bin/ssh-keygen"

echo "--- Setting up OpenSSH Environment ---"

# Ensure directories exist
mkdir -p "$SERVER_ETC"
mkdir -p /var/run/sshd

# 1. Generate Host Keys
echo "[+] Generating Host Keys..."
if [ ! -f "$SERVER_ETC/ssh_host_falcon512_key" ]; then
    "$KEYGEN" -t falcon512 -f "$SERVER_ETC/ssh_host_falcon512_key" -N ""
fi
if [ ! -f "$SERVER_ETC/ssh_host_ed25519_key" ]; then
    "$KEYGEN" -t ed25519 -f "$SERVER_ETC/ssh_host_ed25519_key" -N ""
fi

# 2. Create sshd_config
CONFIG_FILE="$SERVER_ETC/sshd_config"
echo "[+] Creating sshd_config at $CONFIG_FILE..."
cat > "$CONFIG_FILE" <<EOF
Port 2222
HostKey $SERVER_ETC/ssh_host_falcon512_key
HostKey $SERVER_ETC/ssh_host_ed25519_key
AuthorizedKeysFile .ssh/authorized_keys
PidFile /var/run/sshd.pid
Subsystem sftp $SERVER_BASE/libexec/sftp-server
UsePAM yes
PrintMotd yes
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
LogLevel DEBUG3
EOF

# 3. Generate User Keys (for dwq)
echo "[+] Generating User Keys for 'dwq'..."
USER_SSH_DIR="/home/dwq/.ssh"
mkdir -p "$USER_SSH_DIR"

# Falcon512 User Key
"$KEYGEN" -t falcon512 -f "$USER_SSH_DIR/id_falcon512" -N ""
# Ed25519 User Key
"$KEYGEN" -t ed25519 -f "$USER_SSH_DIR/id_ed25519" -N ""

# Authorized Keys
cat "$USER_SSH_DIR/id_falcon512.pub" >> "$USER_SSH_DIR/authorized_keys"
cat "$USER_SSH_DIR/id_ed25519.pub" >> "$USER_SSH_DIR/authorized_keys"
chown -R dwq:dwq /home/dwq

# 4. Start SSHD
echo "[+] Starting SSHD..."
"$SERVER_BIN" -f "$CONFIG_FILE"

echo "[+] Container is ready. SSHD is listening on port 2222."

# Keep alive
tail -f /dev/null
