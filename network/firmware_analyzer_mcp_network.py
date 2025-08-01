#!/usr/bin/env python3
"""
Network-based MCP Server for Firmware Analysis and Password Cracking
This server provides tools to analyze firmware files and extract hardcoded passwords.
"""

import asyncio
import json
import os
import subprocess
import tempfile
import zipfile
import hashlib
import re
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
import magic
from passlib.hash import md5_crypt
import shutil
import socket
import ssl

from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.types import (
    CallToolRequest,
    CallToolResult,
    ListToolsRequest,
    ListToolsResult,
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize the MCP server
server = Server("firmware-analyzer-network")

# Create a simple notification options object
class SimpleNotificationOptions:
    def __init__(self):
        self.tools_changed = False

# Global variables to store extracted files
extracted_files = {}
current_firmware_path = None

@server.list_tools()
async def handle_list_tools() -> ListToolsResult:
    """List all available tools in the MCP server."""
    return ListToolsResult(
        tools=[
            Tool(
                name="update_firmware",
                description="Upload and update firmware (.bin file)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "firmware_path": {
                            "type": "string",
                            "description": "Path to the firmware file (.bin)"
                        }
                    },
                    "required": ["firmware_path"]
                }
            ),
            Tool(
                name="identify_file_format",
                description="Identify the format of uploaded file and handle accordingly",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to the file to analyze"
                        }
                    },
                    "required": ["file_path"]
                }
            ),
            Tool(
                name="extract_with_binwalk",
                description="Use binwalk to recursively extract files from binary",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "binary_path": {
                            "type": "string",
                            "description": "Path to the binary file to extract"
                        }
                    },
                    "required": ["binary_path"]
                }
            ),
            Tool(
                name="extract_squashfs",
                description="Use unsquash tool to open a Squashfs filesystem",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "squashfs_path": {
                            "type": "string",
                            "description": "Path to the squashfs file"
                        }
                    },
                    "required": ["squashfs_path"]
                }
            ),
            Tool(
                name="find_password_files",
                description="Find /etc/passwd and /etc/shadow files in extracted filesystem",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "extracted_path": {
                            "type": "string",
                            "description": "Path to the extracted filesystem"
                        }
                    },
                    "required": ["extracted_path"]
                }
            ),
            Tool(
                name="crack_md5_password",
                description="Try to crack MD5-crypt passwords using various methods",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "password_hash": {
                            "type": "string",
                            "description": "MD5-crypt hash to crack"
                        },
                        "wordlist_path": {
                            "type": "string",
                            "description": "Optional path to wordlist file"
                        }
                    },
                    "required": ["password_hash"]
                }
            )
        ]
    )

@server.call_tool()
async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> CallToolResult:
    """Handle tool calls based on the tool name."""
    
    if name == "update_firmware":
        return await update_firmware(arguments)
    elif name == "identify_file_format":
        return await identify_file_format(arguments)
    elif name == "extract_with_binwalk":
        return await extract_with_binwalk(arguments)
    elif name == "extract_squashfs":
        return await extract_squashfs(arguments)
    elif name == "find_password_files":
        return await find_password_files(arguments)
    elif name == "crack_md5_password":
        return await crack_md5_password(arguments)
    else:
        raise ValueError(f"Unknown tool: {name}")

async def update_firmware(arguments: Dict[str, Any]) -> CallToolResult:
    """Upload and update firmware (.bin file)."""
    global current_firmware_path
    
    firmware_path = arguments["firmware_path"]
    
    if not os.path.exists(firmware_path):
        return CallToolResult(
            content=[
                TextContent(
                    type="text",
                    text=f"Error: Firmware file not found at {firmware_path}"
                )
            ]
        )
    
    # Validate file extension
    if not firmware_path.lower().endswith('.bin'):
        return CallToolResult(
            content=[
                TextContent(
                    type="text",
                    text=f"Warning: File {firmware_path} doesn't have .bin extension"
                )
            ]
        )
    
    current_firmware_path = firmware_path
    
    return CallToolResult(
        content=[
            TextContent(
                type="text",
                text=f"Firmware uploaded successfully: {firmware_path}\nFile size: {os.path.getsize(firmware_path)} bytes"
            )
        ]
    )

async def identify_file_format(arguments: Dict[str, Any]) -> CallToolResult:
    """Identify the format of uploaded file and handle accordingly."""
    file_path = arguments["file_path"]
    
    if not os.path.exists(file_path):
        return CallToolResult(
            content=[
                TextContent(
                    type="text",
                    text=f"Error: File not found at {file_path}"
                )
            ]
        )
    
    # Use python-magic to identify file type
    file_type = magic.from_file(file_path, mime=True)
    file_magic = magic.from_file(file_path)
    
    result_text = f"File: {file_path}\n"
    result_text += f"MIME Type: {file_type}\n"
    result_text += f"Magic Info: {file_magic}\n\n"
    
    # Check if it's a ZIP file
    if file_type == "application/zip" or file_path.lower().endswith('.zip'):
        result_text += "Detected: ZIP file\n"
        result_text += "Action: Extracting ZIP file...\n"
        
        try:
            extract_dir = tempfile.mkdtemp(prefix="firmware_zip_")
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            extracted_files[file_path] = extract_dir
            result_text += f"ZIP extracted to: {extract_dir}\n"
            result_text += "Next step: Use find_password_files tool with the extracted directory path.\n"
            
        except Exception as e:
            result_text += f"Error extracting ZIP: {str(e)}\n"
    
    # Check if it's a SquashFS file
    elif "squashfs" in file_magic.lower() or file_path.lower().endswith('.squashfs'):
        result_text += "Detected: SquashFS filesystem\n"
        result_text += "Action: Use extract_squashfs tool to extract the filesystem.\n"
    
    # Check if it's a binary file
    elif "binary" in file_type or file_type.startswith("application/octet-stream"):
        result_text += "Detected: Binary file\n"
        result_text += "Action: Use extract_with_binwalk tool to analyze and extract contents.\n"
    
    else:
        result_text += f"Unknown file type. Magic info: {file_magic}\n"
        result_text += "Try using extract_with_binwalk tool for binary analysis.\n"
    
    return CallToolResult(
        content=[
            TextContent(
                type="text",
                text=result_text
            )
        ]
    )

async def extract_with_binwalk(arguments: Dict[str, Any]) -> CallToolResult:
    """Use binwalk to recursively extract files from binary."""
    binary_path = arguments["binary_path"]
    
    if not os.path.exists(binary_path):
        return CallToolResult(
            content=[
                TextContent(
                    type="text",
                    text=f"Error: Binary file not found at {binary_path}"
                )
            ]
        )
    
    # Check if binwalk is installed
    try:
        subprocess.run(["binwalk", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return CallToolResult(
            content=[
                TextContent(
                    type="text",
                    text="Error: binwalk is not installed. Please install it first:\n"
                         "sudo apt-get install binwalk\n"
                         "or\n"
                         "pip install binwalk"
                )
            ]
        )
    
    # Create extraction directory
    extract_dir = tempfile.mkdtemp(prefix="binwalk_extract_")
    
    try:
        # Run binwalk extraction
        result = subprocess.run(
            ["binwalk", "-e", binary_path],
            capture_output=True,
            text=True,
            cwd=extract_dir
        )
        
        if result.returncode == 0:
            # Find extracted files
            extracted_items = []
            for root, dirs, files in os.walk(extract_dir):
                for item in dirs + files:
                    item_path = os.path.join(root, item)
                    if os.path.isdir(item_path):
                        extracted_items.append(f"DIR: {os.path.relpath(item_path, extract_dir)}")
                    else:
                        extracted_items.append(f"FILE: {os.path.relpath(item_path, extract_dir)}")
            
            extracted_files[binary_path] = extract_dir
            
            result_text = f"Binwalk extraction completed successfully!\n"
            result_text += f"Extraction directory: {extract_dir}\n\n"
            result_text += "Extracted items:\n"
            for item in extracted_items[:20]:  # Show first 20 items
                result_text += f"  {item}\n"
            
            if len(extracted_items) > 20:
                result_text += f"  ... and {len(extracted_items) - 20} more items\n"
            
            result_text += f"\nNext step: Use find_password_files tool with path: {extract_dir}\n"
            
        else:
            result_text = f"Binwalk extraction failed:\n{result.stderr}"
            
    except Exception as e:
        result_text = f"Error during binwalk extraction: {str(e)}"
    
    return CallToolResult(
        content=[
            TextContent(
                type="text",
                text=result_text
            )
        ]
    )

async def extract_squashfs(arguments: Dict[str, Any]) -> CallToolResult:
    """Use unsquash tool to open a Squashfs filesystem."""
    squashfs_path = arguments["squashfs_path"]
    
    if not os.path.exists(squashfs_path):
        return CallToolResult(
            content=[
                TextContent(
                    type="text",
                    text=f"Error: SquashFS file not found at {squashfs_path}"
                )
            ]
        )
    
    # Check if unsquashfs is installed
    try:
        subprocess.run(["unsquashfs", "-version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return CallToolResult(
            content=[
                TextContent(
                    type="text",
                    text="Error: unsquashfs is not installed. Please install it first:\n"
                         "sudo apt-get install squashfs-tools"
                )
            ]
        )
    
    # Create extraction directory
    extract_dir = tempfile.mkdtemp(prefix="squashfs_extract_")
    
    try:
        # Run unsquashfs extraction
        result = subprocess.run(
            ["unsquashfs", "-d", extract_dir, squashfs_path],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            extracted_files[squashfs_path] = extract_dir
            
            result_text = f"SquashFS extraction completed successfully!\n"
            result_text += f"Extraction directory: {extract_dir}\n\n"
            result_text += "Next step: Use find_password_files tool with path: {extract_dir}\n"
            
        else:
            result_text = f"SquashFS extraction failed:\n{result.stderr}"
            
    except Exception as e:
        result_text = f"Error during SquashFS extraction: {str(e)}"
    
    return CallToolResult(
        content=[
            TextContent(
                type="text",
                text=result_text
            )
        ]
    )

async def find_password_files(arguments: Dict[str, Any]) -> CallToolResult:
    """Find /etc/passwd and /etc/shadow files in extracted filesystem."""
    extracted_path = arguments["extracted_path"]
    
    if not os.path.exists(extracted_path):
        return CallToolResult(
            content=[
                TextContent(
                    type="text",
                    text=f"Error: Extracted path not found at {extracted_path}"
                )
            ]
        )
    
    result_text = f"Searching for password files in: {extracted_path}\n\n"
    
    passwd_files = []
    shadow_files = []
    
    # Search for passwd and shadow files
    for root, dirs, files in os.walk(extracted_path):
        for file in files:
            if file == "passwd":
                passwd_path = os.path.join(root, file)
                passwd_files.append(passwd_path)
            elif file == "shadow":
                shadow_path = os.path.join(root, file)
                shadow_files.append(shadow_path)
    
    result_text += f"Found {len(passwd_files)} passwd file(s):\n"
    for passwd_file in passwd_files:
        result_text += f"  {passwd_file}\n"
        try:
            with open(passwd_file, 'r') as f:
                content = f.read()
                result_text += f"    Content preview:\n"
                for line in content.split('\n')[:5]:  # Show first 5 lines
                    if line.strip():
                        result_text += f"      {line}\n"
                if len(content.split('\n')) > 5:
                    result_text += f"      ... and {len(content.split('\n')) - 5} more lines\n"
        except Exception as e:
            result_text += f"    Error reading file: {str(e)}\n"
    
    result_text += f"\nFound {len(shadow_files)} shadow file(s):\n"
    for shadow_file in shadow_files:
        result_text += f"  {shadow_file}\n"
        try:
            with open(shadow_file, 'r') as f:
                content = f.read()
                result_text += f"    Content preview:\n"
                for line in content.split('\n')[:5]:  # Show first 5 lines
                    if line.strip():
                        # Mask the hash for security
                        parts = line.split(':')
                        if len(parts) >= 2:
                            masked_line = f"{parts[0]}:{'*' * 20}:{':'.join(parts[2:])}"
                            result_text += f"      {masked_line}\n"
                        else:
                            result_text += f"      {line}\n"
                if len(content.split('\n')) > 5:
                    result_text += f"      ... and {len(content.split('\n')) - 5} more lines\n"
        except Exception as e:
            result_text += f"    Error reading file: {str(e)}\n"
    
    if not passwd_files and not shadow_files:
        result_text += "No passwd or shadow files found.\n"
    
    return CallToolResult(
        content=[
            TextContent(
                type="text",
                text=result_text
            )
        ]
    )

async def crack_md5_password(arguments: Dict[str, Any]) -> CallToolResult:
    """Try to crack MD5-crypt passwords using various methods."""
    password_hash = arguments["password_hash"]
    wordlist_path = arguments.get("wordlist_path")
    
    result_text = f"Attempting to crack MD5-crypt hash: {password_hash}\n\n"
    
    # Validate hash format
    if not password_hash.startswith('$1$'):
        result_text += "Warning: This doesn't appear to be an MD5-crypt hash (should start with $1$)\n"
    
    # Common passwords to try
    common_passwords = [
        "admin", "root", "password", "123456", "admin123", "root123",
        "password123", "123456789", "qwerty", "abc123", "letmein",
        "welcome", "monkey", "dragon", "master", "firmware", "device",
        "default", "system", "user", "guest", "test", "demo", "setup",
        "config", "router", "gateway", "modem", "switch", "hub"
    ]
    
    result_text += "Trying common passwords...\n"
    
    # Try common passwords
    for password in common_passwords:
        try:
            if md5_crypt.verify(password, password_hash):
                result_text += f"SUCCESS! Password found: {password}\n"
                return CallToolResult(
                    content=[
                        TextContent(
                            type="text",
                            text=result_text
                        )
                    ]
                )
        except Exception as e:
            continue
    
    result_text += "Common passwords failed. Trying wordlist...\n"
    
    # Try wordlist if provided
    if wordlist_path and os.path.exists(wordlist_path):
        try:
            with open(wordlist_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    password = line.strip()
                    if password:
                        try:
                            if md5_crypt.verify(password, password_hash):
                                result_text += f"SUCCESS! Password found: {password} (line {line_num})\n"
                                return CallToolResult(
                                    content=[
                                        TextContent(
                                            type="text",
                                            text=result_text
                                        )
                                    ]
                                )
                        except Exception:
                            continue
                        
                        if line_num % 1000 == 0:
                            result_text += f"Tried {line_num} passwords...\n"
        except Exception as e:
            result_text += f"Error reading wordlist: {str(e)}\n"
    
    # Try brute force with simple patterns
    result_text += "Trying simple brute force patterns...\n"
    
    # Try numbers
    for i in range(1000):
        password = str(i)
        try:
            if md5_crypt.verify(password, password_hash):
                result_text += f"SUCCESS! Password found: {password}\n"
                return CallToolResult(
                    content=[
                        TextContent(
                            type="text",
                            text=result_text
                        )
                    ]
                )
        except Exception:
            continue
    
    result_text += "Password cracking failed. The password might be:\n"
    result_text += "1. Not in the common password list\n"
    result_text += "2. Not in the provided wordlist\n"
    result_text += "3. Too complex for simple brute force\n"
    result_text += "4. Not actually an MD5-crypt hash\n"
    
    return CallToolResult(
        content=[
            TextContent(
                type="text",
                text=result_text
            )
        ]
    )

class NetworkMCPServer:
    def __init__(self, host='0.0.0.0', port=8080, use_ssl=False, cert_file=None, key_file=None):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.cert_file = cert_file
        self.key_file = key_file
        self.server = None
        
    async def handle_client(self, reader, writer):
        """Handle individual client connections."""
        client_addr = writer.get_extra_info('peername')
        logger.info(f"New client connected from {client_addr}")
        
        try:
            # Create a new server instance for this client
            client_server = Server("firmware-analyzer-network")
            
            # Register the same handlers
            @client_server.list_tools()
            async def client_list_tools() -> ListToolsResult:
                return await handle_list_tools()
            
            @client_server.call_tool()
            async def client_call_tool(name: str, arguments: Dict[str, Any]) -> CallToolResult:
                return await handle_call_tool(name, arguments)
            
            # Run the server for this client
            await client_server.run(
                reader,
                writer,
                InitializationOptions(
                    server_name="firmware-analyzer-network",
                    server_version="1.0.0",
                    capabilities=client_server.get_capabilities(
                        notification_options=SimpleNotificationOptions(),
                        experimental_capabilities=None,
                    ),
                ),
            )
            
        except Exception as e:
            logger.error(f"Error handling client {client_addr}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            logger.info(f"Client {client_addr} disconnected")
    
    async def start_server(self):
        """Start the network MCP server."""
        try:
            if self.use_ssl:
                if not self.cert_file or not self.key_file:
                    raise ValueError("SSL requires both cert_file and key_file")
                
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                context.load_cert_chain(self.cert_file, self.key_file)
                
                self.server = await asyncio.start_server(
                    self.handle_client,
                    self.host,
                    self.port,
                    ssl=context
                )
                logger.info(f"SSL MCP Server started on {self.host}:{self.port}")
            else:
                self.server = await asyncio.start_server(
                    self.handle_client,
                    self.host,
                    self.port
                )
                logger.info(f"MCP Server started on {self.host}:{self.port}")
            
            async with self.server:
                await self.server.serve_forever()
                
        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            raise

async def main():
    """Main function to run the network MCP server."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Network-based MCP Firmware Analyzer Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8080, help='Port to bind to (default: 8080)')
    parser.add_argument('--ssl', action='store_true', help='Enable SSL/TLS')
    parser.add_argument('--cert', help='SSL certificate file')
    parser.add_argument('--key', help='SSL private key file')
    
    args = parser.parse_args()
    
    # Validate SSL arguments
    if args.ssl and (not args.cert or not args.key):
        logger.error("SSL requires both --cert and --key arguments")
        return
    
    # Create and start the server
    server = NetworkMCPServer(
        host=args.host,
        port=args.port,
        use_ssl=args.ssl,
        cert_file=args.cert,
        key_file=args.key
    )
    
    try:
        await server.start_server()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")

if __name__ == "__main__":
    asyncio.run(main()) 