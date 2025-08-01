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
from aiohttp import web, WSMsgType, MultipartReader
import aiohttp_cors
import ssl

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global variables to store extracted files and uploaded files
extracted_files = {}
current_firmware_path = None
uploaded_files = {}  # Store uploaded file paths

# Create a simple notification options object
class SimpleNotificationOptions:
    def __init__(self):
        self.tools_changed = False

async def handle_file_upload(request):
    """Handle file upload via multipart form data."""
    try:
        # Create upload directory if it doesn't exist
        upload_dir = Path("uploads")
        upload_dir.mkdir(exist_ok=True)
        
        # Read multipart data
        reader = await request.multipart()
        
        uploaded_file_path = None
        file_info = {}
        
        async for field in reader:
            if field.name == 'file':
                # Get file info
                filename = field.filename
                if not filename:
                    return web.json_response({"error": "No file provided"})
                
                # Create unique filename
                file_ext = Path(filename).suffix
                unique_filename = f"{hashlib.md5(filename.encode()).hexdigest()[:8]}_{int(asyncio.get_event_loop().time())}{file_ext}"
                file_path = upload_dir / unique_filename
                
                # Save uploaded file
                with open(file_path, 'wb') as f:
                    while True:
                        chunk = await field.read_chunk(8192)
                        if not chunk:
                            break
                        f.write(chunk)
                
                uploaded_file_path = str(file_path)
                file_info = {
                    "original_name": filename,
                    "saved_path": uploaded_file_path,
                    "file_size": os.path.getsize(uploaded_file_path),
                    "upload_time": asyncio.get_event_loop().time()
                }
                
                # Store file info
                uploaded_files[uploaded_file_path] = file_info
                
                logger.info(f"File uploaded: {filename} -> {uploaded_file_path}")
                break
        
        if uploaded_file_path:
            return web.json_response({
                "success": True,
                "message": f"File uploaded successfully: {file_info['original_name']}",
                "file_info": file_info
            })
        else:
            return web.json_response({"error": "No file received"})
            
    except Exception as e:
        logger.error(f"File upload error: {e}")
        return web.json_response({"error": f"Upload failed: {str(e)}"})

async def update_firmware(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Upload and update firmware (.bin file)."""
    global current_firmware_path
    
    firmware_path = arguments.get("firmware_path")
    
    # Check if it's an uploaded file ID
    if firmware_path and firmware_path.startswith("upload_"):
        # Extract file path from uploaded files
        for file_path, file_info in uploaded_files.items():
            if file_info.get("original_name") == firmware_path.replace("upload_", ""):
                firmware_path = file_path
                break
    
    if not firmware_path or not os.path.exists(firmware_path):
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
    file_path = arguments.get("file_path")
    
    # Check if it's an uploaded file ID
    if file_path and file_path.startswith("upload_"):
        # Extract file path from uploaded files
        for path, file_info in uploaded_files.items():
            if file_info.get("original_name") == file_path.replace("upload_", ""):
                file_path = path
                break
    
    if not file_path or not os.path.exists(file_path):
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
    binary_path = arguments.get("binary_path")
    
    # Check if it's an uploaded file ID
    if binary_path and binary_path.startswith("upload_"):
        # Extract file path from uploaded files
        for path, file_info in uploaded_files.items():
            if file_info.get("original_name") == binary_path.replace("upload_", ""):
                binary_path = path
                break
    
    if not binary_path or not os.path.exists(binary_path):
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
    squashfs_path = arguments.get("squashfs_path")
    
    # Check if it's an uploaded file ID
    if squashfs_path and squashfs_path.startswith("upload_"):
        # Extract file path from uploaded files
        for path, file_info in uploaded_files.items():
            if file_info.get("original_name") == squashfs_path.replace("upload_", ""):
                squashfs_path = path
                break
    
    if not squashfs_path or not os.path.exists(squashfs_path):
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
    extracted_path = arguments.get("extracted_path")
    
    if not extracted_path or not os.path.exists(extracted_path):
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
    password_hash = arguments.get("password_hash")
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

async def handle_uploaded_files(request):
    """Get list of uploaded files."""
    try:
        files_list = []
        for file_path, file_info in uploaded_files.items():
            files_list.append({
                "id": f"upload_{file_info['original_name']}",
                "name": file_info['original_name'],
                "path": file_path,
                "size": file_info['file_size'],
                "upload_time": file_info['upload_time']
            })
        
        return web.json_response({
            "success": True,
            "files": files_list
        })
    except Exception as e:
        return web.json_response({"error": str(e)})

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
            input, textarea, select { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 3px; }
            button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 3px; cursor: pointer; margin: 5px; }
            button:hover { background: #0056b3; }
            .result { margin-top: 15px; padding: 10px; background: #f8f9fa; border-radius: 3px; white-space: pre-wrap; }
            .error { color: red; }
            .success { color: green; }
            .file-upload { border: 2px dashed #ddd; padding: 20px; text-align: center; border-radius: 5px; }
            .file-upload.dragover { border-color: #007bff; background: #f0f8ff; }
            .uploaded-files { margin: 10px 0; }
            .file-item { padding: 5px; background: #f8f9fa; margin: 2px 0; border-radius: 3px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔍 Firmware Analyzer MCP Server</h1>
            <p>Network-based firmware analysis and password extraction tool with file upload support.</p>
            
            <div class="tool">
                <h3>📁 File Upload</h3>
                <div class="file-upload" id="fileUpload">
                    <p>Drag and drop firmware files here or click to select</p>
                    <input type="file" id="fileInput" style="display: none;" accept=".bin,.zip,.img,.firmware,.fw,.rom,.hex,.srec,.ihex">
                    <button onclick="document.getElementById('fileInput').click()">Select File</button>
                </div>
                <div id="uploadedFiles" class="uploaded-files"></div>
                <div id="upload_result" class="result"></div>
            </div>
            
            <div class="tool">
                <h3>1. Update Firmware</h3>
                <div class="input-group">
                    <label>Firmware File:</label>
                    <select id="firmware_select">
                        <option value="">Select uploaded file or enter path</option>
                    </select>
                    <input type="text" id="firmware_path" placeholder="Or enter file path: /path/to/firmware.bin">
                </div>
                <button onclick="updateFirmware()">Update Firmware</button>
                <div id="update_result" class="result"></div>
            </div>
            
            <div class="tool">
                <h3>2. Identify File Format</h3>
                <div class="input-group">
                    <label>File:</label>
                    <select id="file_select">
                        <option value="">Select uploaded file or enter path</option>
                    </select>
                    <input type="text" id="file_path" placeholder="Or enter file path: /path/to/file">
                </div>
                <button onclick="identifyFormat()">Identify Format</button>
                <div id="format_result" class="result"></div>
            </div>
            
            <div class="tool">
                <h3>3. Extract with Binwalk</h3>
                <div class="input-group">
                    <label>Binary File:</label>
                    <select id="binary_select">
                        <option value="">Select uploaded file or enter path</option>
                    </select>
                    <input type="text" id="binary_path" placeholder="Or enter file path: /path/to/binary">
                </div>
                <button onclick="extractBinwalk()">Extract</button>
                <div id="binwalk_result" class="result"></div>
            </div>
            
            <div class="tool">
                <h3>4. Extract SquashFS</h3>
                <div class="input-group">
                    <label>SquashFS File:</label>
                    <select id="squashfs_select">
                        <option value="">Select uploaded file or enter path</option>
                    </select>
                    <input type="text" id="squashfs_path" placeholder="Or enter file path: /path/to/squashfs">
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
            // File upload handling
            const fileUpload = document.getElementById('fileUpload');
            const fileInput = document.getElementById('fileInput');
            
            fileUpload.addEventListener('dragover', (e) => {
                e.preventDefault();
                fileUpload.classList.add('dragover');
            });
            
            fileUpload.addEventListener('dragleave', () => {
                fileUpload.classList.remove('dragover');
            });
            
            fileUpload.addEventListener('drop', (e) => {
                e.preventDefault();
                fileUpload.classList.remove('dragover');
                const files = e.dataTransfer.files;
                if (files.length > 0) {
                    uploadFile(files[0]);
                }
            });
            
            fileInput.addEventListener('change', (e) => {
                if (e.target.files.length > 0) {
                    uploadFile(e.target.files[0]);
                }
            });
            
            async function uploadFile(file) {
                const formData = new FormData();
                formData.append('file', file);
                
                try {
                    const response = await fetch('/api/upload', {
                        method: 'POST',
                        body: formData
                    });
                    
                    const result = await response.json();
                    document.getElementById('upload_result').textContent = JSON.stringify(result, null, 2);
                    
                    if (result.success) {
                        loadUploadedFiles();
                    }
                } catch (error) {
                    document.getElementById('upload_result').textContent = JSON.stringify({error: error.message}, null, 2);
                }
            }
            
            async function loadUploadedFiles() {
                try {
                    const response = await fetch('/api/uploaded-files');
                    const result = await response.json();
                    
                    if (result.success) {
                        const filesList = result.files.map(f => 
                            `<div class="file-item">📁 ${f.name} (${formatFileSize(f.size)})</div>`
                        ).join('');
                        
                        document.getElementById('uploadedFiles').innerHTML = filesList;
                        
                        // Update select dropdowns
                        updateSelectDropdowns(result.files);
                    }
                } catch (error) {
                    console.error('Error loading uploaded files:', error);
                }
            }
            
            function updateSelectDropdowns(files) {
                const selects = ['firmware_select', 'file_select', 'binary_select', 'squashfs_select'];
                
                selects.forEach(selectId => {
                    const select = document.getElementById(selectId);
                    select.innerHTML = '<option value="">Select uploaded file or enter path</option>';
                    
                    files.forEach(file => {
                        const option = document.createElement('option');
                        option.value = `upload_${file.name}`;
                        option.textContent = `${file.name} (${formatFileSize(file.size)})`;
                        select.appendChild(option);
                    });
                });
            }
            
            function formatFileSize(bytes) {
                if (bytes === 0) return '0 Bytes';
                const k = 1024;
                const sizes = ['Bytes', 'KB', 'MB', 'GB'];
                const i = Math.floor(Math.log(bytes) / Math.log(k));
                return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
            }
            
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
                const selectValue = document.getElementById('firmware_select').value;
                const pathValue = document.getElementById('firmware_path').value;
                const firmwarePath = selectValue || pathValue;
                
                const result = await callTool('update_firmware', { firmware_path: firmwarePath });
                document.getElementById('update_result').textContent = JSON.stringify(result, null, 2);
            }
            
            async function identifyFormat() {
                const selectValue = document.getElementById('file_select').value;
                const pathValue = document.getElementById('file_path').value;
                const filePath = selectValue || pathValue;
                
                const result = await callTool('identify_file_format', { file_path: filePath });
                document.getElementById('format_result').textContent = JSON.stringify(result, null, 2);
            }
            
            async function extractBinwalk() {
                const selectValue = document.getElementById('binary_select').value;
                const pathValue = document.getElementById('binary_path').value;
                const binaryPath = selectValue || pathValue;
                
                const result = await callTool('extract_with_binwalk', { binary_path: binaryPath });
                document.getElementById('binwalk_result').textContent = JSON.stringify(result, null, 2);
            }
            
            async function extractSquashfs() {
                const selectValue = document.getElementById('squashfs_select').value;
                const pathValue = document.getElementById('squashfs_path').value;
                const squashfsPath = selectValue || pathValue;
                
                const result = await callTool('extract_squashfs', { squashfs_path: squashfsPath });
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
            
            // Load uploaded files on page load
            loadUploadedFiles();
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
                        "description": "Path to the firmware file (.bin) or uploaded file ID"
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
                        "description": "Path to the file to analyze or uploaded file ID"
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
                        "description": "Path to the binary file to extract or uploaded file ID"
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
                        "description": "Path to the squashfs file or uploaded file ID"
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

# MCP Protocol endpoints for GitHub Copilot
async def handle_mcp_initialize(request):
    """Handle MCP initialize request."""
    try:
        data = await request.json()
        
        # MCP initialize response
        response = {
            "jsonrpc": "2.0",
            "id": data.get("id"),
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "firmware-analyzer-mcp",
                    "version": "1.0.0"
                }
            }
        }
        
        return web.json_response(response)
    except Exception as e:
        return web.json_response({
            "jsonrpc": "2.0",
            "id": data.get("id") if 'data' in locals() else None,
            "error": {
                "code": -32603,
                "message": f"Internal error: {str(e)}"
            }
        })

async def handle_mcp_tools_list(request):
    """Handle MCP tools/list request."""
    try:
        data = await request.json()
        
        tools = [
            {
                "name": "update_firmware",
                "description": "Upload and update firmware (.bin file)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "firmware_path": {
                            "type": "string",
                            "description": "Path to the firmware file (.bin) or uploaded file ID"
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
                            "description": "Path to the file to analyze or uploaded file ID"
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
                            "description": "Path to the binary file to extract or uploaded file ID"
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
                            "description": "Path to the squashfs file or uploaded file ID"
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
        
        response = {
            "jsonrpc": "2.0",
            "id": data.get("id"),
            "result": {
                "tools": tools
            }
        }
        
        return web.json_response(response)
    except Exception as e:
        return web.json_response({
            "jsonrpc": "2.0",
            "id": data.get("id") if 'data' in locals() else None,
            "error": {
                "code": -32603,
                "message": f"Internal error: {str(e)}"
            }
        })

async def handle_mcp_tools_call(request):
    """Handle MCP tools/call request."""
    try:
        data = await request.json()
        
        method = data.get("params", {}).get("name")
        arguments = data.get("params", {}).get("arguments", {})
        
        # Map MCP tool calls to our functions
        tool_handlers = {
            "update_firmware": update_firmware,
            "identify_file_format": identify_file_format,
            "extract_with_binwalk": extract_with_binwalk,
            "extract_squashfs": extract_squashfs,
            "find_password_files": find_password_files,
            "crack_md5_password": crack_md5_password
        }
        
        if method in tool_handlers:
            result = await tool_handlers[method](arguments)
            response = {
                "jsonrpc": "2.0",
                "id": data.get("id"),
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, indent=2)
                        }
                    ]
                }
            }
        else:
            response = {
                "jsonrpc": "2.0",
                "id": data.get("id"),
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}"
                }
            }
        
        return web.json_response(response)
    except Exception as e:
        return web.json_response({
            "jsonrpc": "2.0",
            "id": data.get("id") if 'data' in locals() else None,
            "error": {
                "code": -32603,
                "message": f"Internal error: {str(e)}"
            }
        })

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
    app.router.add_post('/api/upload', handle_file_upload)
    app.router.add_get('/api/uploaded-files', handle_uploaded_files)
    app.router.add_get('/api/tools/list', handle_tools_list)
    app.router.add_post('/api/update_firmware', handle_update_firmware)
    app.router.add_post('/api/identify_file_format', handle_identify_file_format)
    app.router.add_post('/api/extract_with_binwalk', handle_extract_with_binwalk)
    app.router.add_post('/api/extract_squashfs', handle_extract_squashfs)
    app.router.add_post('/api/find_password_files', handle_find_password_files)
    app.router.add_post('/api/crack_md5_password', handle_crack_md5_password)
    
    # MCP Protocol routes for GitHub Copilot
    app.router.add_post('/mcp/initialize', handle_mcp_initialize)
    app.router.add_post('/mcp/tools/list', handle_mcp_tools_list)
    app.router.add_post('/mcp/tools/call', handle_mcp_tools_call)
    
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