#!/bin/bash

# Tell the user that the program is running
echo "COMP5700 Group Project - Starting..."

# Verify that python and pip are installed
if ! command -v python3 >/dev/null 2>&1; then
  echo "WARNING: python3 is not installed. Exiting."
  exit 1
elif ! command -v pip3 >/dev/null 2>&1; then
  echo "WARNING: pip3 is not installed. Exiting."
  exit 1
fi

# Verify that kubescape is installed, and prompt the user to install it if it isn't
if ! command -v kubescape >/dev/null 2>&1; then
  echo "WARNING: kubescape is not installed"
  read -n 1 -p "kubescape is not installed, would you like to install it? [y/n]   " decision
  echo

  # Install it using the command from the kubescape GitHub repo if wanted
  # Otherwise exit
  if [ "${decision,,}" = "y" ]; then
    curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
    export PATH=$PATH:$HOME/.kubescape/bin
    # Verify that the installation was successful
    command -v kubescape >/dev/null 2>&1 || { echo "Kubescape installation failed. Exiting."; exit 1; }
    echo "Kubescape installed successfully."
  else
    echo "Skipping kubescape installation. Exiting."
    exit 1
  fi
fi

# Create the python virtual environment
echo "Creating virtual environment"
python3 -m venv project5700-venv

# Source the python virtual environment
echo "Sourcing virtual environment"
source project5700-venv/bin/activate

# Install requirements
echo "Installing requirements"
pip3 install -r ./requirements.txt

# Install pyinstaller
echo "Installing pyinstaller"
pip3 install -U pyinstaller

# Build the binary
echo "Building binary"
pyinstaller --onefile --name 5700-project main.py

# Verify the build succeeded
BINARY="./dist/5700-project"
if [ ! -f "$BINARY" ]; then
  echo "ERROR: Build failed, binary not found at $BINARY. Exiting."
  exit 1
fi
echo "Build successful!"

# Specify to the user how to enter the file paths to the pdfs
# This is based off of the examples given in task-4, which state that
# "the TA will provide nine inputs each of which includes two PDF files:"
# with the example input of "cis-r1.pdf and cis-r2.pdf"
echo
echo "Enter the input combinations to be sent to the python program"
echo "   For each input combination, separate file paths with 'and'."
echo "   Ex: './cis-r1.pdf and ./cis-r2.pdf'"
echo

# Loop through the program to run it 9 times, each with unique input
for i in {1..9};
do
  read -a input_array -p "   Enter input combination $i:   "
  pdf1="${input_array[0]}"
  pdf2="${input_array[2]}"

  # Validate that both paths were provided
  if [ -z "$pdf1" ] || [ -z "$pdf2" ]; then
    echo "   ERROR: Invalid input. Expected format: 'path1 and path2'. Skipping."
    continue
  fi

  echo "   Running: $BINARY $pdf1 $pdf2"
  "$BINARY" "$pdf1" "$pdf2"
done