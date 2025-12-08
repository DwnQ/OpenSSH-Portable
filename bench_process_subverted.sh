
for f in benchmark/conn_*.log; do
    out="${f%.log}_processed.log"
    grep -E "debug3: kyber:|debug3: falcon:" "$f" > "$out"
done