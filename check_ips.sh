#!/bin/bash
# This script will create one process for each IP
# and cycle through all the informed RBLs.

LINE_NUM=1

while read LINE
do
    ./dnsbl.sh $LINE &
    ((LINE_NUM++))
done < ./ip_list

# wait for all the processes to finish
wait
