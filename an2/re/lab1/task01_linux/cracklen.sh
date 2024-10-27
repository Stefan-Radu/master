#!/usr/bin/env bash

for i in {0..10000}; do
    #[ $(($i % 10)) -eq 0 ] && echo $i
    line_count=$(printf "%0*d\n" ${i} | ltrace -c ./crackme 2>&1 | wc -l)

    if [ $line_count -ne 9 ]; then
        printf "found length: %d" $i
        exit 0
    fi
done
