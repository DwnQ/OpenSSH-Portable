
for f in benchmark_subverted/conn_*.log; do
    out="${f%.log}_processed.log"
    grep -E "debug3: kyber:|debug3: falcon:" "$f" > "$out"
done