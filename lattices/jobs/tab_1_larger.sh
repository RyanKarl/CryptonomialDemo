#!/bin/bash

#$ -M jtakeshi@nd.edu
#$ -m abe
#$ -q *@@jung
#$ -pe smp 1
#$ -N tab_1_larger
#

SCHEMES=("BGV", "BFV")
BACKENDS="-r -g -p"
#Run from root directory
EXECUTABLE=./slap
ITERATIONS=5


SUBFOLDER=tab_1

mkdir -p ./results/${SUBFOLDER}/
module load gcc/9.1.0

PLAIN=128
USERS=100000

time $EXECUTABLE -t $PLAIN -n $USERS -i $ITERATIONS $BACKENDS -c BGV > ./results/${SUBFOLDER}/${PLAIN}_${USERS}_bgv.txt
time $EXECUTABLE -t $PLAIN -n $USERS -i $ITERATIONS $BACKENDS -c BFV > ./results/${SUBFOLDER}/${PLAIN}_${USERS}_bfv.txt
python stats.py ./results/${SUBFOLDER}/${PLAIN}_${USERS}_*.txt > ./results/${SUBFOLDER}/${PLAIN}_${USERS}.rep
echo "Finished ${PLAIN} ${USERS}"

USERS=1000000

time $EXECUTABLE -t $PLAIN -n $USERS -i $ITERATIONS $BACKENDS -c BGV > ./results/${SUBFOLDER}/${PLAIN}_${USERS}_bgv.txt
time $EXECUTABLE -t $PLAIN -n $USERS -i $ITERATIONS $BACKENDS -c BFV > ./results/${SUBFOLDER}/{PLAIN}_${USERS}_bfv.txt
python stats.py ./results/${SUBFOLDER}/${PLAIN}_${USERS}_*.txt > ./results/${SUBFOLDER}/${PLAIN}_${USERS}.rep
echo "Finished ${PLAIN} ${USERS}"

USERS=10000000

time $EXECUTABLE -t $PLAIN -n $USERS -i $ITERATIONS $BACKENDS -c BGV > ./results/${SUBFOLDER}/${PLAIN}_${USERS}_bgv.txt
time $EXECUTABLE -t $PLAIN -n $USERS -i $ITERATIONS $BACKENDS -c BFV > ./results/${SUBFOLDER}/{PLAIN}_${USERS}_bfv.txt
python stats.py ./results/${SUBFOLDER}/${PLAIN}_${USERS}_*.txt > ./results/${SUBFOLDER}/${PLAIN}_${USERS}.rep
echo "Finished ${PLAIN} ${USERS}"

USERS=100000000

time $EXECUTABLE -t $PLAIN -n $USERS -i $ITERATIONS $BACKENDS -c BGV > ./results/${SUBFOLDER}/${PLAIN}_${USERS}_bgv.txt
time $EXECUTABLE -t $PLAIN -n $USERS -i $ITERATIONS $BACKENDS -c BFV > ./results/${SUBFOLDER}/{PLAIN}_${USERS}_bfv.txt
python stats.py ./results/${SUBFOLDER}/${PLAIN}_${USERS}_*.txt > ./results/${SUBFOLDER}/${PLAIN}_${USERS}.rep
echo "Finished ${PLAIN} ${USERS}"

