#!/bin/bash

#$ -M jtakeshi@nd.edu
#$ -m abe
#$ -q *@@jung
#$ -pe smp 1
#$ -N incr_t
#

SCHEMES=("BGV", "BFV")
BACKENDS="-r -g -p"
#Run from root directory
EXECUTABLE=./slap
declare -a PLAIN_SIZES=("32" "64" "128" "196")
PACKED_SIZE=16
NUM_USERS=1000 #About 10 bits
ITERATIONS=50


SUBFOLDER=increasing_plain

mkdir -p ./results/${SUBFOLDER}/
module load gcc/9.1.0

for i in "${PLAIN_SIZES[@]}":
  do
    time $EXECUTABLE -t $i -w $PACKED_SIZE -n $NUM_USERS -i $ITERATIONS $BACKENDS -c BGV > ./results/${SUBFOLDER}/incr_plain_${i}_bgv.txt
    time $EXECUTABLE -t $i -w $PACKED_SIZE -n $NUM_USERS -i $ITERATIONS $BACKENDS -c BFV > ./results/${SUBFOLDER}/incr_plain_${i}_bfv.txt
done

python stats.py ./results/${SUBFOLDER}/*.txt > ./results/${SUBFOLDER}/incr_plain.rep

