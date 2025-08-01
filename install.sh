#!/bin/bash

# Firmware Analyzer MCP Server Installation Script

echo "=== Firmware Analyzer MCP Server Installation ==="

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "Please don't run this script as root"
    exit 1
fi

# Detect OS
if [ -f /etc/debian_version ]; then
    OS="debian"
elif [ -f /etc/redhat-release ]; then
    OS="redhat"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    OS="unknown"
fi

echo "Detected OS: $OS"

# Install system dependencies
echo "Installing system dependencies..."

case $OS in
    "debian")
        sudo apt-get update
        sudo apt-get install -y binwalk squashfs-tools python3-magic libmagic1
        ;;
    "redhat")
        sudo yum install -y binwalk squashfs-tools python3-magic
        ;;
    "macos")
        if ! command -v brew &> /dev/null; then
            echo "Homebrew not found. Please install it first: https://brew.sh/"
            exit 1
        fi
        brew install binwalk squashfs-tools
        ;;
    *)
        echo "Unsupported OS. Please install dependencies manually:"
        echo "- binwalk"
        echo "- squashfs-tools"
        echo "- python3-magic"
        ;;
esac

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install -r requirements.txt

# Make the MCP server executable
chmod +x firmware_analyzer_mcp.py

# Create a simple wordlist for testing
echo "Creating test wordlist..."
cat > test_wordlist.txt << EOF
admin
root
password
123456
admin123
root123
password123
123456789
qwerty
abc123
letmein
welcome
monkey
dragon
master
firmware
device
default
system
user
guest
test
demo
setup
config
router
gateway
modem
switch
hub
EOF

echo "Installation completed!"
echo ""
echo "To test the installation, run:"
echo "python3 test_firmware_analyzer.py"
echo ""
echo "To start the MCP server, run:"
echo "python3 firmware_analyzer_mcp.py"
echo ""
echo "For usage instructions, see README.md" 