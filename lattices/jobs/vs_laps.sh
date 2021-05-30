#!/bin/bash

#$ -M jtakeshi@nd.edu
#$ -m abe
#$ -q *@@jung
#$ -pe smp 1
#$ -N vs_laps
#

SCHEMES=("BGV", "BFV")
BACKENDS="-g -r -p"
#Run from root directory
EXECUTABLE=./slap
PLAIN_SIZE=32
MESSAGE_SIZE=16
NUM_USERS=1000
ITERATIONS=100


SUBFOLDER=laps_comparison

mkdir -p ./results/${SUBFOLDER}/
module load gcc/9.1.0

time $EXECUTABLE -t $PLAIN_SIZE -w $MESSAGE_SIZE -n $NUM_USERS -i $ITERATIONS $BACKENDS -c BGV > ./results/${SUBFOLDER}/laps_vs_bgv.txt
time $EXECUTABLE -t $PLAIN_SIZE -w $MESSAGE_SIZE -n $NUM_USERS -i $ITERATIONS $BACKENDS -c BFV > ./results/${SUBFOLDER}/laps_vs_bfv.txt

python stats.py ./results/${SUBFOLDER}/*.txt > ./results/${SUBFOLDER}/laps.rep

