#!/bin/bash

#$ -M jtakeshi@nd.edu
#$ -m abe
#$ -q *@@jung
#$ -pe smp 1
#$ -N incr_users
#

SCHEMES=("BGV", "BFV")
BACKENDS="-r -g -p"
#Run from root directory
EXECUTABLE=./slap
PLAIN_SIZE=64
PACK_SIZE=16
declare -a USERS_LIST=("1000" "10000" "100000" "1000000")
ITERATIONS=50


SUBFOLDER=increasing_users

mkdir -p ./results/${SUBFOLDER}/
module load gcc/9.1.0

for i in "${USERS_LIST[@]}":
  do
    time $EXECUTABLE -t $PLAIN_SIZE -w $PACK_SIZE -n $i -i $ITERATIONS $BACKENDS -c BGV > ./results/${SUBFOLDER}/incr_n_${i}_bgv.txt
    time $EXECUTABLE -t $PLAIN_SIZE -w $PACK_SIZE -n $i -i $ITERATIONS $BACKENDS -c BFV > ./results/${SUBFOLDER}/incr_n_${i}_bfv.txt
done

python stats.py ./results/${SUBFOLDER}/*.txt > ./results/${SUBFOLDER}/incr_users.rep

