#!/bin/bash
# Formatting variables
INFO='\033[0;36m'
WARNING='\033[0;31m'
SUCCESS='\033[0;32m'
CLEAR='\033[0m'
# Tell the user that the program is running
echo "COMP5700 Group Project - Starting..."

# Verify that python and pip are installed
if ! command -v python3 >/dev/null 2>&1; then
  echo -e "${WARNING}WARNING: python3 is not installed. Exiting.${CLEAR}"
  exit 1
elif ! command -v pip3 >/dev/null 2>&1; then
  echo -e "${WARNING}WARNING: pip3 is not installed. Exiting.${CLEAR}"
  exit 1
fi

# Verify that kubescape is installed, and prompt the user to install it if it isn't
if ! command -v kubescape >/dev/null 2>&1; then
  echo -e "${WARNING}WARNING: kubescape is not installed${CLEAR}"
  read -n 1 -p "kubescape is not installed, would you like to install it? [y/n]   " decision
  echo

  # Install it using the command from the kubescape GitHub repo if wanted
  # Otherwise exit
  if [ "${decision,,}" = "y" ]; then
    curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
    export PATH=$PATH:$HOME/.kubescape/bin
    # Verify that the installation was successful
    command -v kubescape >/dev/null 2>&1 || { echo -e "${WARNING}Kubescape installation failed. Exiting.${CLEAR}"; exit 1; }
    echo -e "${SUCCESS}Kubescape installed successfully.${CLEAR}"
  else
    echo "Skipping kubescape installation. Exiting."
    exit 1
  fi
fi

# Verify that HF_TOKEN is set
if [ -z "$HF_TOKEN" ]; then
  echo -e "${WARNING}WARNING: HF_TOKEN environment variable is not set.${CLEAR}"
  read -p "   Enter your HuggingFace token: " HF_TOKEN
  if [ -z "$HF_TOKEN" ]; then
    echo -e "${WARNING}ERROR: No token provided. Exiting.${CLEAR}"
    exit 1
  fi
  export HF_TOKEN
fi

# Create the python virtual environment
if [ ! -d "project5700-venv" ]; then
  echo -e "${INFO}Creating virtual environment...${CLEAR}"
  python3 -m venv project5700-venv
else
  echo -e "${INFO}Virtual environment already exists, skipping creation.${CLEAR}"
fi

# Source the python virtual environment
echo -e "${INFO}Sourcing virtual environment${CLEAR}"
source project5700-venv/bin/activate

# Install requirements
echo -e "${INFO}Installing requirements${CLEAR}"
pip3 install -r ./requirements.txt

# Install pyinstaller
echo -e "${INFO}Installing pyinstaller${CLEAR}"
pip3 install -U pyinstaller

# Build the binary
echo -e "${INFO}Building binary${CLEAR}"
pyinstaller --onefile --name 5700-project main.py > /dev/null 2>&1

# Verify the build succeeded
BINARY="./dist/5700-project"
if [ ! -f "$BINARY" ]; then
  echo -e "${WARNING}ERROR: Build failed, binary not found at $BINARY. Exiting.${CLEAR}"
  exit 1
fi
echo -e "${SUCCESS}Build successful!${CLEAR}"

# Specify to the user how to enter the file paths to the pdfs
# This is based off of the examples given in task-4, which state that
# "the TA will provide nine inputs each of which includes two PDF files:"
# with the example input of "cis-r1.pdf and cis-r2.pdf"
echo
echo -e "${INFO}Enter the input combinations to be sent to the python program${CLEAR}"
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
    echo -e "   ${WARNING}ERROR: Invalid input. Expected format: 'path1 and path2'. Skipping.${CLEAR}"
    ((i--))  # retry this iteration
    continue
  fi

  echo "   Running: $BINARY $pdf1 $pdf2"
  "$BINARY" "$pdf1" "$pdf2"
  echo
done