
for f in benchmark_original/conn_*.log; do
    out="${f%.log}_processed.log"
    grep -E "debug3: mlkem:|debug3: ed25519:" "$f" > "$out"
done