#!/bin/bash

# --- Configuration ---
DIR_ORIG="benchmark_original"
DIR_SUB="benchmark_subverted"
OUT_FILE="benchmark_full.out"

# Initialize arrays
mlkem_times=()
ed25519_times=()
kyber_times=()
falcon_times=()

# --- Extraction Function ---
extract_span() {
    log="$1"
    start_pat="$2"
    end_pat="$3"

    # HEAD -n1 gets the VERY FIRST occurrence (Start of the sequence)
    ts_start=$(grep -E "$start_pat" "$log" | grep -oP '\[\K[0-9\-: .]+' | head -n1)
    
    # TAIL -n1 gets the VERY LAST occurrence (End of the sequence)
    ts_end=$(grep -E "$end_pat" "$log" | grep -oP '\[\K[0-9\-: .]+' | tail -n1)

    if [ -z "$ts_start" ] || [ -z "$ts_end" ]; then
        return
    fi

    start_ns=$(date -d "$ts_start" +%s%N)
    end_ns=$(date -d "$ts_end" +%s%N)
    
    # Sanity check: If end is before start, we ignore this sample
    if [ "$end_ns" -lt "$start_ns" ]; then
        return
    fi

    # Calculate microseconds
    dur_us=$(( (end_ns - start_ns) / 1000 ))
    echo "$dur_us"
}

# --- Main Execution ---

# 1. Process Original Folder
echo "Processing $DIR_ORIG..."
logs_orig=$(ls $DIR_ORIG/conn_*_processed.log 2>/dev/null)

if [ -n "$logs_orig" ]; then
    for f in $logs_orig; do
        # MLKEM: Full Span (Keypair Start -> Decapsulation End)
        val=$(extract_span "$f" "mlkem:.*keypair start" "mlkem:.*decapsulation end")
        [ -n "$val" ] && mlkem_times+=("$val")

        # Ed25519: Full Span (First Deserialize -> Sign End)
        val=$(extract_span "$f" "ed25519:.*deserialize_pub" "ed25519:.*sign:end")
        [ -n "$val" ] && ed25519_times+=("$val")
    done
fi

# 2. Process Subverted Folder
echo "Processing $DIR_SUB..."
logs_sub=$(ls $DIR_SUB/conn_*_processed.log 2>/dev/null)

if [ -n "$logs_sub" ]; then
    for f in $logs_sub; do
        # Kyber: Full Span (Keypair Start -> Decapsulation End)
        val=$(extract_span "$f" "kyber:.*keypair start" "kyber:.*decapsulation end")
        [ -n "$val" ] && kyber_times+=("$val")

        # Falcon: Full Span (First op -> Sign End)
        # Assuming Falcon logs start with deserialize/verify just like Ed25519
        val=$(extract_span "$f" "falcon:" "falcon:.*sign:en[gd]")
        [ -n "$val" ] && falcon_times+=("$val")
    done
fi

# --- Statistics Function (Style Preserved) ---
calc_stats() {
    arr=("$@")
    count=${#arr[@]}

    if [ "$count" -eq 0 ]; then
        echo "No samples."
        return
    fi

    sorted=($(printf "%s\n" "${arr[@]}" | sort -n))
    min=${sorted[0]}
    max=${sorted[$((count-1))]}
    avg=$(printf "%s\n" "${sorted[@]}" | awk '{sum+=$1} END {print int(sum/NR)}')

    q1=${sorted[$((count/4))]}
    median=${sorted[$((count/2))]}
    q3=${sorted[$((3*count/4))]}

    echo "Samples:      $count"
    echo "Minimum (µs): $min"
    echo "Q1 (µs):      $q1"
    echo "Median (µs):  $median"
    echo "Q3 (µs):      $q3"
    echo "Maximum (µs): $max"
    echo "Mean (µs):    $avg"
}

# --- Write Output to File ---
{
    echo "Benchmark Results Generated on $(date)"
    echo "------------------------------------------------"
    
    echo
    echo "====== ORIGINAL: MLKEM (Full Span) ======"
    calc_stats "${mlkem_times[@]}"

    echo
    echo "====== ORIGINAL: Ed25519 (Full Span) ======"
    calc_stats "${ed25519_times[@]}"

    echo
    echo "====== SUBVERTED: Kyber (Full Span) ======"
    calc_stats "${kyber_times[@]}"

    echo
    echo "====== SUBVERTED: Falcon (Full Span) ======"
    calc_stats "${falcon_times[@]}"

} > "$OUT_FILE"

echo "Done! Results saved to $OUT_FILE"
