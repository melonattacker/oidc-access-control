#!/bin/bash

# Initialize the CSV file
csv_file="./evaluation/data/performance/resource/proposed/resource_after_siginin_confidential.csv"

# Create the CSV file with header if it does not exist
if [ ! -f "$csv_file" ]; then
    echo "Creating CSV file: $csv_file"
    mkdir -p $(dirname "$csv_file")
    echo "Sequence,CPU Usage (%),Memory Usage (MB)" > "$csv_file"
fi

# Specify tmp file pattern
temp_file_pattern="/tmp/hogehoge/tmp*"

# Wait for the tmp file to be created
while true; do
    temp_file=$(ls $temp_file_pattern 2> /dev/null | head -n 1)
    if [[ -f "$temp_file" ]]; then
        echo "Found temporary file: $temp_file"
        break
    else
        echo "Waiting for the temporary file to be created..."
        sleep 1
    fi
done

counter=1

while [ -f "$temp_file" ]; do
    # Run the docker stats command non-interactively and capture the output once
    stats=$(docker stats --no-stream --format "table {{.CPUPerc}}\t{{.MemUsage}}" rp)

    # Sum up the CPU and memory usage
    cpu_total=$(echo "$stats" | awk 'NR>1 {gsub(/%/,""); total += $1} END {print total}')
    mem_usage_total=$(echo "$stats" | awk 'NR>1 {split($2,a,"/"); total += a[1]} END {print total}')

    echo "Total CPU Usage: $cpu_total%"
    echo "Total Memory Usage: $mem_usage_total MB"
    echo "--------------------------"

    # Write to the CSV file
    echo "$counter,$cpu_total,$mem_usage_total" >> $csv_file

    # Increment the counter
    ((counter++))

    # Wait for 1 second
    sleep 1
done
