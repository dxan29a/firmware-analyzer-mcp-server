#!/usr/bin/env python3
"""
Streaming HTTP-based MCP Server for Firmware Analysis and Password Cracking
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
from aiohttp import web, WSMsgType
import aiohttp_cors
import ssl

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global variables to store extracted files
extracted_files = {}
current_firmware_path = None

# Create a simple notification options object
class SimpleNotificationOptions:
    def __init__(self):
        self.tools_changed = False

async def update_firmware(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Upload and update firmware (.bin file)."""
    global current_firmware_path
    
    firmware_path = arguments["firmware_path"]
    
    if not os.path.exists(firmware_path):
        return {
            "error": f"Firmware file not found at {firmware_path}"
        }
    
    # Validate file extension
    if not firmware_path.lower().endswith('.bin'):
        return {
            "warning": f"File {firmware_path} doesn't have .bin extension",
            "firmware_path": firmware_path,
            "file_size": os.path.getsize(firmware_path)
        }
    
    current_firmware_path = firmware_path
    
    return {
        "success": True,
        "message": f"Firmware uploaded successfully: {firmware_path}",
        "file_size": os.path.getsize(firmware_path)
    }

async def identify_file_format(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Identify the format of uploaded file and handle accordingly."""
    file_path = arguments["file_path"]
    
    if not os.path.exists(file_path):
        return {
            "error": f"File not found at {file_path}"
        }
    
    # Use python-magic to identify file type
    file_type = magic.from_file(file_path, mime=True)
    file_magic = magic.from_file(file_path)
    
    result = {
        "file": file_path,
        "mime_type": file_type,
        "magic_info": file_magic,
        "detected_format": None,
        "extracted_path": None,
        "next_step": None
    }
    
    # Check if it's a ZIP file
    if file_type == "application/zip" or file_path.lower().endswith('.zip'):
        result["detected_format"] = "ZIP"
        result["next_step"] = "Use find_password_files tool with the extracted directory path"
        
        try:
            extract_dir = tempfile.mkdtemp(prefix="firmware_zip_")
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            extracted_files[file_path] = extract_dir
            result["extracted_path"] = extract_dir
            result["message"] = f"ZIP extracted to: {extract_dir}"
            
        except Exception as e:
            result["error"] = f"Error extracting ZIP: {str(e)}"
    
    # Check if it's a SquashFS file
    elif "squashfs" in file_magic.lower() or file_path.lower().endswith('.squashfs'):
        result["detected_format"] = "SquashFS"
        result["next_step"] = "Use extract_squashfs tool to extract the filesystem"
    
    # Check if it's a binary file
    elif "binary" in file_type or file_type.startswith("application/octet-stream"):
        result["detected_format"] = "Binary"
        result["next_step"] = "Use extract_with_binwalk tool to analyze and extract contents"
    
    else:
        result["detected_format"] = "Unknown"
        result["next_step"] = "Try using extract_with_binwalk tool for binary analysis"
    
    return result

async def extract_with_binwalk(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Use binwalk to recursively extract files from binary."""
    binary_path = arguments["binary_path"]
    
    if not os.path.exists(binary_path):
        return {
            "error": f"Binary file not found at {binary_path}"
        }
    
    # Check if binwalk is installed
    try:
        subprocess.run(["binwalk", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {
            "error": "binwalk is not installed. Please install it first:\n"
                     "sudo apt-get install binwalk\n"
                     "or\n"
                     "pip install binwalk"
        }
    
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
            
            return {
                "success": True,
                "message": "Binwalk extraction completed successfully!",
                "extraction_directory": extract_dir,
                "extracted_items": extracted_items[:20],  # Show first 20 items
                "total_items": len(extracted_items),
                "next_step": f"Use find_password_files tool with path: {extract_dir}"
            }
            
        else:
            return {
                "error": f"Binwalk extraction failed:\n{result.stderr}"
            }
            
    except Exception as e:
        return {
            "error": f"Error during binwalk extraction: {str(e)}"
        }

async def extract_squashfs(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Use unsquash tool to open a Squashfs filesystem."""
    squashfs_path = arguments["squashfs_path"]
    
    if not os.path.exists(squashfs_path):
        return {
            "error": f"SquashFS file not found at {squashfs_path}"
        }
    
    # Check if unsquashfs is installed
    try:
        subprocess.run(["unsquashfs", "-version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {
            "error": "unsquashfs is not installed. Please install it first:\n"
                     "sudo apt-get install squashfs-tools"
        }
    
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
            
            return {
                "success": True,
                "message": "SquashFS extraction completed successfully!",
                "extraction_directory": extract_dir,
                "next_step": f"Use find_password_files tool with path: {extract_dir}"
            }
            
        else:
            return {
                "error": f"SquashFS extraction failed:\n{result.stderr}"
            }
            
    except Exception as e:
        return {
            "error": f"Error during SquashFS extraction: {str(e)}"
        }

async def find_password_files(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Find /etc/passwd and /etc/shadow files in extracted filesystem."""
    extracted_path = arguments["extracted_path"]
    
    if not os.path.exists(extracted_path):
        return {
            "error": f"Extracted path not found at {extracted_path}"
        }
    
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
    
    result = {
        "search_path": extracted_path,
        "passwd_files": [],
        "shadow_files": [],
        "total_passwd": len(passwd_files),
        "total_shadow": len(shadow_files)
    }
    
    # Process passwd files
    for passwd_file in passwd_files:
        file_info = {"path": passwd_file, "content": []}
        try:
            with open(passwd_file, 'r') as f:
                content = f.read()
                lines = content.split('\n')
                file_info["content"] = lines[:5]  # Show first 5 lines
                file_info["total_lines"] = len(lines)
        except Exception as e:
            file_info["error"] = str(e)
        result["passwd_files"].append(file_info)
    
    # Process shadow files
    for shadow_file in shadow_files:
        file_info = {"path": shadow_file, "content": []}
        try:
            with open(shadow_file, 'r') as f:
                content = f.read()
                lines = content.split('\n')
                # Mask the hash for security
                masked_lines = []
                for line in lines[:5]:  # Show first 5 lines
                    if line.strip():
                        parts = line.split(':')
                        if len(parts) >= 2:
                            masked_line = f"{parts[0]}:{'*' * 20}:{':'.join(parts[2:])}"
                            masked_lines.append(masked_line)
                        else:
                            masked_lines.append(line)
                file_info["content"] = masked_lines
                file_info["total_lines"] = len(lines)
        except Exception as e:
            file_info["error"] = str(e)
        result["shadow_files"].append(file_info)
    
    if not passwd_files and not shadow_files:
        result["message"] = "No passwd or shadow files found."
    
    return result

async def crack_md5_password(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Try to crack MD5-crypt passwords using various methods."""
    password_hash = arguments["password_hash"]
    wordlist_path = arguments.get("wordlist_path")
    
    result = {
        "hash": password_hash,
        "methods_tried": [],
        "cracked": False,
        "password": None
    }
    
    # Validate hash format
    if not password_hash.startswith('$1$'):
        result["warning"] = "This doesn't appear to be an MD5-crypt hash (should start with $1$)"
    
    # Common passwords to try
    common_passwords = [
        "admin", "root", "password", "123456", "admin123", "root123",
        "password123", "123456789", "qwerty", "abc123", "letmein",
        "welcome", "monkey", "dragon", "master", "firmware", "device",
        "default", "system", "user", "guest", "test", "demo", "setup",
        "config", "router", "gateway", "modem", "switch", "hub"
    ]
    
    result["methods_tried"].append("common_passwords")
    
    # Try common passwords
    for password in common_passwords:
        try:
            if md5_crypt.verify(password, password_hash):
                result["cracked"] = True
                result["password"] = password
                result["method"] = "common_passwords"
                return result
        except Exception:
            continue
    
    # Try wordlist if provided
    if wordlist_path and os.path.exists(wordlist_path):
        result["methods_tried"].append("wordlist")
        try:
            with open(wordlist_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    password = line.strip()
                    if password:
                        try:
                            if md5_crypt.verify(password, password_hash):
                                result["cracked"] = True
                                result["password"] = password
                                result["method"] = "wordlist"
                                result["line_number"] = line_num
                                return result
                        except Exception:
                            continue
        except Exception as e:
            result["wordlist_error"] = str(e)
    
    # Try brute force with simple patterns
    result["methods_tried"].append("brute_force")
    
    # Try numbers
    for i in range(1000):
        password = str(i)
        try:
            if md5_crypt.verify(password, password_hash):
                result["cracked"] = True
                result["password"] = password
                result["method"] = "brute_force"
                return result
        except Exception:
            continue
    
    result["message"] = "Password cracking failed. The password might be:\n" \
                       "1. Not in the common password list\n" \
                       "2. Not in the provided wordlist\n" \
                       "3. Too complex for simple brute force\n" \
                       "4. Not actually an MD5-crypt hash"
    
    return result

# HTTP route handlers
async def handle_index(request):
    """Serve the main HTML page."""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Firmware Analyzer MCP Server</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .container { max-width: 800px; margin: 0 auto; }
            .tool { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
            .input-group { margin: 10px 0; }
            label { display: block; margin-bottom: 5px; font-weight: bold; }
            input, textarea { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 3px; }
            button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 3px; cursor: pointer; }
            button:hover { background: #0056b3; }
            .result { margin-top: 15px; padding: 10px; background: #f8f9fa; border-radius: 3px; white-space: pre-wrap; }
            .error { color: red; }
            .success { color: green; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔍 Firmware Analyzer MCP Server</h1>
            <p>Network-based firmware analysis and password extraction tool.</p>
            
            <div class="tool">
                <h3>1. Update Firmware</h3>
                <div class="input-group">
                    <label>Firmware Path:</label>
                    <input type="text" id="firmware_path" placeholder="/path/to/firmware.bin">
                </div>
                <button onclick="updateFirmware()">Update Firmware</button>
                <div id="update_result" class="result"></div>
            </div>
            
            <div class="tool">
                <h3>2. Identify File Format</h3>
                <div class="input-group">
                    <label>File Path:</label>
                    <input type="text" id="file_path" placeholder="/path/to/file">
                </div>
                <button onclick="identifyFormat()">Identify Format</button>
                <div id="format_result" class="result"></div>
            </div>
            
            <div class="tool">
                <h3>3. Extract with Binwalk</h3>
                <div class="input-group">
                    <label>Binary Path:</label>
                    <input type="text" id="binary_path" placeholder="/path/to/binary">
                </div>
                <button onclick="extractBinwalk()">Extract</button>
                <div id="binwalk_result" class="result"></div>
            </div>
            
            <div class="tool">
                <h3>4. Extract SquashFS</h3>
                <div class="input-group">
                    <label>SquashFS Path:</label>
                    <input type="text" id="squashfs_path" placeholder="/path/to/squashfs">
                </div>
                <button onclick="extractSquashfs()">Extract</button>
                <div id="squashfs_result" class="result"></div>
            </div>
            
            <div class="tool">
                <h3>5. Find Password Files</h3>
                <div class="input-group">
                    <label>Extracted Path:</label>
                    <input type="text" id="extracted_path" placeholder="/path/to/extracted">
                </div>
                <button onclick="findPasswords()">Find Passwords</button>
                <div id="password_result" class="result"></div>
            </div>
            
            <div class="tool">
                <h3>6. Crack MD5 Password</h3>
                <div class="input-group">
                    <label>Password Hash:</label>
                    <input type="text" id="password_hash" placeholder="$1$salt$hash">
                </div>
                <div class="input-group">
                    <label>Wordlist Path (optional):</label>
                    <input type="text" id="wordlist_path" placeholder="/path/to/wordlist.txt">
                </div>
                <button onclick="crackPassword()">Crack Password</button>
                <div id="crack_result" class="result"></div>
            </div>
        </div>
        
        <script>
            async function callTool(toolName, arguments) {
                try {
                    const response = await fetch(`/api/${toolName}`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify(arguments)
                    });
                    
                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }
                    
                    const result = await response.json();
                    return result;
                } catch (error) {
                    return { error: error.message };
                }
            }
            
            async function updateFirmware() {
                const path = document.getElementById('firmware_path').value;
                const result = await callTool('update_firmware', { firmware_path: path });
                document.getElementById('update_result').textContent = JSON.stringify(result, null, 2);
            }
            
            async function identifyFormat() {
                const path = document.getElementById('file_path').value;
                const result = await callTool('identify_file_format', { file_path: path });
                document.getElementById('format_result').textContent = JSON.stringify(result, null, 2);
            }
            
            async function extractBinwalk() {
                const path = document.getElementById('binary_path').value;
                const result = await callTool('extract_with_binwalk', { binary_path: path });
                document.getElementById('binwalk_result').textContent = JSON.stringify(result, null, 2);
            }
            
            async function extractSquashfs() {
                const path = document.getElementById('squashfs_path').value;
                const result = await callTool('extract_squashfs', { squashfs_path: path });
                document.getElementById('squashfs_result').textContent = JSON.stringify(result, null, 2);
            }
            
            async function findPasswords() {
                const path = document.getElementById('extracted_path').value;
                const result = await callTool('find_password_files', { extracted_path: path });
                document.getElementById('password_result').textContent = JSON.stringify(result, null, 2);
            }
            
            async function crackPassword() {
                const hash = document.getElementById('password_hash').value;
                const wordlist = document.getElementById('wordlist_path').value;
                const args = { password_hash: hash };
                if (wordlist) args.wordlist_path = wordlist;
                const result = await callTool('crack_md5_password', args);
                document.getElementById('crack_result').textContent = JSON.stringify(result, null, 2);
            }
        </script>
    </body>
    </html>
    """
    return web.Response(text=html_content, content_type='text/html')

async def handle_update_firmware(request):
    """Handle update_firmware tool call."""
    try:
        data = await request.json()
        result = await update_firmware(data)
        return web.json_response(result)
    except Exception as e:
        return web.json_response({"error": str(e)})

async def handle_identify_file_format(request):
    """Handle identify_file_format tool call."""
    try:
        data = await request.json()
        result = await identify_file_format(data)
        return web.json_response(result)
    except Exception as e:
        return web.json_response({"error": str(e)})

async def handle_extract_with_binwalk(request):
    """Handle extract_with_binwalk tool call."""
    try:
        data = await request.json()
        result = await extract_with_binwalk(data)
        return web.json_response(result)
    except Exception as e:
        return web.json_response({"error": str(e)})

async def handle_extract_squashfs(request):
    """Handle extract_squashfs tool call."""
    try:
        data = await request.json()
        result = await extract_squashfs(data)
        return web.json_response(result)
    except Exception as e:
        return web.json_response({"error": str(e)})

async def handle_find_password_files(request):
    """Handle find_password_files tool call."""
    try:
        data = await request.json()
        result = await find_password_files(data)
        return web.json_response(result)
    except Exception as e:
        return web.json_response({"error": str(e)})

async def handle_crack_md5_password(request):
    """Handle crack_md5_password tool call."""
    try:
        data = await request.json()
        result = await crack_md5_password(data)
        return web.json_response(result)
    except Exception as e:
        return web.json_response({"error": str(e)})

async def handle_tools_list(request):
    """Handle tools/list request."""
    tools = [
        {
            "name": "update_firmware",
            "description": "Upload and update firmware (.bin file)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "firmware_path": {
                        "type": "string",
                        "description": "Path to the firmware file (.bin)"
                    }
                },
                "required": ["firmware_path"]
            }
        },
        {
            "name": "identify_file_format",
            "description": "Identify the format of uploaded file and handle accordingly",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file to analyze"
                    }
                },
                "required": ["file_path"]
            }
        },
        {
            "name": "extract_with_binwalk",
            "description": "Use binwalk to recursively extract files from binary",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "binary_path": {
                        "type": "string",
                        "description": "Path to the binary file to extract"
                    }
                },
                "required": ["binary_path"]
            }
        },
        {
            "name": "extract_squashfs",
            "description": "Use unsquash tool to open a Squashfs filesystem",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "squashfs_path": {
                        "type": "string",
                        "description": "Path to the squashfs file"
                    }
                },
                "required": ["squashfs_path"]
            }
        },
        {
            "name": "find_password_files",
            "description": "Find /etc/passwd and /etc/shadow files in extracted filesystem",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "extracted_path": {
                        "type": "string",
                        "description": "Path to the extracted filesystem"
                    }
                },
                "required": ["extracted_path"]
            }
        },
        {
            "name": "crack_md5_password",
            "description": "Try to crack MD5-crypt passwords using various methods",
            "inputSchema": {
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
        }
    ]
    
    return web.json_response({"tools": tools})

async def init_app():
    """Initialize the web application."""
    app = web.Application()
    
    # Add CORS support
    cors = aiohttp_cors.setup(app, defaults={
        "*": aiohttp_cors.ResourceOptions(
            allow_credentials=True,
            expose_headers="*",
            allow_headers="*",
            allow_methods="*"
        )
    })
    
    # Add routes
    app.router.add_get('/', handle_index)
    app.router.add_get('/api/tools/list', handle_tools_list)
    app.router.add_post('/api/update_firmware', handle_update_firmware)
    app.router.add_post('/api/identify_file_format', handle_identify_file_format)
    app.router.add_post('/api/extract_with_binwalk', handle_extract_with_binwalk)
    app.router.add_post('/api/extract_squashfs', handle_extract_squashfs)
    app.router.add_post('/api/find_password_files', handle_find_password_files)
    app.router.add_post('/api/crack_md5_password', handle_crack_md5_password)
    
    # Add CORS to all routes
    for route in list(app.router.routes()):
        cors.add(route)
    
    return app

def main():
    """Main function to run the HTTP MCP server."""
    import argparse
    
    parser = argparse.ArgumentParser(description='HTTP-based MCP Firmware Analyzer Server')
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
    
    # Create and run the server
    app = init_app()
    
    try:
        if args.ssl:
            web.run_app(
                app,
                host=args.host,
                port=args.port,
                ssl_context=ssl.create_default_context(ssl.Purpose.CLIENT_AUTH).load_cert_chain(args.cert, args.key)
            )
            logger.info(f"SSL HTTP MCP Server started on {args.host}:{args.port}")
        else:
            web.run_app(app, host=args.host, port=args.port)
            logger.info(f"HTTP MCP Server started on {args.host}:{args.port}")
            
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")

if __name__ == "__main__":
    main() 