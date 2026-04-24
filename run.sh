#!/bin/bash

# Tell the user that the program is running
echo "COMP5700 Group Project - Starting..."

# Verify that python, pip, and kubescape are installed
if ! command -v python3 >/dev/null 2>&1; then
  echo "WARNING: python3 is not installed. Exiting."
  exit 1
elif ! command -v pip3 >/dev/null 2>&1; then
  echo "WARNING: pip3 is not installed. Exiting."
  exit 1
elif ! command -v kubescape >/dev/null 2>&1; then
  echo "WARNING: kubescape is not installed. Exiting."
  exit 1
fi

# Create the python virtual environment
echo "Creating virtual environment"
python3 -m venv project5700-venv

# Source the python virtual environment
echo "Sourcing virtual environment"
source project5700-venv/bin/activate

# Install requirements
pip3 install -r ./requirements.txt

# Specify to the user how to enter the file paths to the pdfs
# This is based off of the examples given in task-4, which state that
# "the TA will provide nine inputs each of which includes two PDF files:"
# with the example input of "cis-r1.pdf and cis-r2.pdf"
echo "For each input combination, separate file paths with 'and'."
echo "Ex: './cis-r1.pdf and ./cis-r2.pdf'"

# Loop through the program to run it 9 times, each with unique input
for i in {1..9};
do
  read -a input_array -p "Enter input combination $i:   "
  echo ${input_array[0]}
  echo ${input_array[2]}
done