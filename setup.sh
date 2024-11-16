#!/bin/bash

# Define package lists
LINUX_PACKAGES=("gcc-arm-none-eabi" "gcc-msp430")
PYTHON_PACKAGES=("keystone-engine" "pyelftools")

# Function to check Linux packages
check_linux_packages() {
    echo "Checking Ubuntu packages..."
    for pkg in "${LINUX_PACKAGES[@]}"; do
        if dpkg -l | grep -q "^ii  $pkg"; then
            echo "$pkg is installed."
        else
            echo "$pkg is NOT installed !!!"
        fi
    done
}

# Function to check Python packages
check_python_packages() {
    echo "Checking Python packages..."
    for pkg in "${PYTHON_PACKAGES[@]}"; do
        if python3 -m pip show "$pkg" &> /dev/null; then
            echo "$pkg is installed."
        else
            echo "$pkg is NOT installed !!!"
        fi
    done
}

# Check Linux and Python packages
check_linux_packages
echo ""
check_python_packages

