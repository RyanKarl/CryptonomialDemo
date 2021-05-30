#!/bin/bash

#$ -M jtakeshi@nd.edu
#$ -m abe
#$ -q *@@jung
#$ -pe smp 1
#$ -N find_roots
#

declare -a ARGS=("2048 0x3fffffff000001" "4096 0xffffee001" "4096 0xffffc4001" "4096 0x1ffffe0001" "8192 0x7fffffd8001" "8192 0x7fffffc8001" "8192 0xfffffffc001" "8192 0xffffff6c001" "8192 0xfffffebc001" "16384 0xfffffffd8001" "16384 0xfffffffa0001" "16384 0xfffffff00001" "16384 0x1fffffff68001" "16384 0x1fffffff50001" "16384 0x1ffffffee8001" "16384 0x1ffffffea0001" "16384 0x1ffffffe88001" "16384 0x1ffffffe48001" "32768 0x7fffffffe90001" "32768 0x7fffffffbf0001" "32768 0x7fffffffbd0001" "32768 0x7fffffffba0001" "32768 0x7fffffffaa0001" "32768 0x7fffffffa50001" "32768 0x7fffffff9f0001" "32768 0x7fffffff7e0001" "32768 0x7fffffff770001" "32768 0x7fffffff380001" "32768 0x7fffffff330001" "32768 0x7fffffff2d0001" "32768 0x7fffffff170001" "32768 0x7fffffff150001" "32768 0x7ffffffef00001" "32768 0xfffffffff70001") 

SUBFOLDER=root_out
EXECUTABLE=./roots
#RESULTS_OUTFILE=./results/out.txt

module load gcc/9.1.0

mkdir -p ./results/${SUBFOLDER}/

for i in "${ARGS[@]}"
do
	vals=($i)
	echo $i
	echo ${vals[1]}
	time $EXECUTABLE $i > ./results/${SUBFOLDER}/${vals[1]}
done

