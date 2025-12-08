
for f in benchmark2/conn_*.log; do
    out="${f%.log}_processed.log"
    grep -E "debug3: ed25519:|debug3: falcon:" "$f" > "$out"
done