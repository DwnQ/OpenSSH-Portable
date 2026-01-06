#!/bin/bash
set -e

echo "============================================"
echo "   OpenSSH PQC Benchmark - Full Setup"
echo "============================================"

# Step 1: Setup sshd_config with port 2222
echo "[1/8] Configuring sshd..."
cat > /opt/customsshServer/etc/sshd_config << 'EOF'
Port 2222
PermitRootLogin yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PubkeyAcceptedAlgorithms +pqc-falcon512
HostKeyAlgorithms +pqc-falcon512
EOF

# Step 2: Kill existing sshd and restart
echo "[2/8] Starting sshd on port 2222..."
pkill sshd 2>/dev/null || true
/opt/customsshServer/sbin/sshd

# Step 3: Generate keys
echo "[3/8] Generating SSH keys..."
mkdir -p ~/.ssh
if [ ! -f ~/.ssh/id_falcon512 ]; then
    /opt/customsshClient/bin/ssh-keygen -t falcon512 -f ~/.ssh/id_falcon512 -N ""
fi
if [ ! -f ~/.ssh/id_ed25519 ]; then
    /opt/customsshClient/bin/ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""
fi

# Step 4: Setup authorized_keys
echo "[4/8] Setting up authorized_keys..."
cat ~/.ssh/id_falcon512.pub >> ~/.ssh/authorized_keys 2>/dev/null || true
cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys 2>/dev/null || true
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys

# Step 5: Test connection
echo "[5/8] Testing SSH connection..."
/opt/customsshClient/bin/ssh -p 2222 -o StrictHostKeyChecking=no -o BatchMode=yes \
  -i ~/.ssh/id_ed25519 $(whoami)@127.0.0.1 "echo 'SSH connection: SUCCESS'"

echo ""
echo "Setup complete! Running benchmarks..."
echo ""

cd /src

# Step 6: Run benchmarks
echo "[6/8] Running healthy benchmark (mlkem768x25519 + ed25519)..."
./benchmark_healthy.sh
echo "      Done!"

echo "[6/8] Running subverted benchmark (mlkemcustom + falcon512)..."
./benchmark_subverted.sh
echo "      Done!"

# Step 7: Process results
echo "[7/8] Processing benchmark logs..."
./bench_process.sh
./bench_process_subverted.sh
echo "      Done!"

# Step 8: Generate statistics
echo "[8/8] Generating statistics..."
./bench_stats.sh
echo "      Done!"

echo ""
echo "============================================"
echo "       All Benchmarks Complete!"
echo "============================================"
echo ""
echo "Results saved to: benchmark_full.out"
echo ""
echo "To generate plot, run:"
echo "  python3 bench_plot.py"
