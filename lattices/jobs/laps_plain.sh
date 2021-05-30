#!/bin/bash

#$ -M jtakeshi@nd.edu
#$ -m abe
#$ -q *@@jung
#$ -pe smp 1
#$ -N laps_plain
#

BACKENDS="-p"
#Run from root directory
EXECUTABLE=./slap
PLAIN_SIZE=32
MESSAGE_SIZE=16
NUM_USERS=1000
ITERATIONS=100


SUBFOLDER=laps_comparison

mkdir -p ./results/${SUBFOLDER}/
module load gcc/9.1.0

time $EXECUTABLE -t $PLAIN_SIZE -w $MESSAGE_SIZE -n $NUM_USERS -i $ITERATIONS $BACKENDS > ./results/${SUBFOLDER}/laps_plain.txt

python stats.py ./results/${SUBFOLDER}/*.txt > ./results/${SUBFOLDER}/laps.rep

