#!/bin/bash

logs=$(ls benchmark_subverted/conn_*_processed.log 2>/dev/null)
[ -z "$logs" ] && echo "No logs found." && exit 1

falcon_times=()
kyber_times=()

extract_us() {
    log="$1"
    tag="$2"

    ts_list=$(grep "debug3: $tag:" "$log" | grep -oP '\[\K[0-9\-: .]+')
    [ -z "$ts_list" ] && echo "" && return

    first=$(printf "%s\n" "$ts_list" | head -n1)
    last=$(printf "%s\n" "$ts_list" | tail -n1)

    first_ns=$(date -d "$first" +%s%N)
    last_ns=$(date -d "$last" +%s%N)

    dur_us=$(( (last_ns - first_ns) / 1000 ))
    echo "$dur_us"
}

for f in $logs; do
    f_us=$(extract_us "$f" "falcon")
    k_us=$(extract_us "$f" "kyber")

    [ -n "$f_us" ] && falcon_times+=("$f_us")
    [ -n "$k_us" ] && kyber_times+=("$k_us")
done

calc_stats() {
    arr=("$@")
    count=${#arr[@]}

    [ "$count" -eq 0 ] && echo "No samples." && return

    sorted=($(printf "%s\n" "${arr[@]}" | sort -n))
    min=${sorted[0]}
    max=${sorted[$((count-1))]}
    avg=$(printf "%s\n" "${sorted[@]}" | awk '{sum+=$1} END {print sum/NR}')

    q1=${sorted[$((count/4))]}
    median=${sorted[$((count/2))]}
    q3=${sorted[$((3*count/4))]}
    p99=${sorted[$((count*99/100))]}

    echo "Samples: $count"
    echo "Minimum (µs):       $min"
    echo "Q1 (µs):            $q1"
    echo "Median (µs):        $median"
    echo "Q3 (µs):            $q3"
    echo "Maximum (µs):       $max"
    echo "Mean (µs):          $avg"
}

echo "====== KYBER ======"
calc_stats "${kyber_times[@]}"

echo
echo "====== FALCON ======"
calc_stats "${falcon_times[@]}"
