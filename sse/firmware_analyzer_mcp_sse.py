#!/usr/bin/env python3
"""
SSE (Server-Sent Events) based MCP Server for Firmware Analysis and Password Cracking
This server provides tools to analyze firmware files and extract hardcoded passwords.
Uses SSE for real-time communication with VS Code GitHub Copilot extension.
"""

import asyncio
import json
import os
import subprocess
import tempfile
import time
import zipfile
import hashlib
import re
import logging
import uuid
import aiohttp
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
import magic
from passlib.hash import md5_crypt
import shutil
from aiohttp import web, WSMsgType, MultipartReader
import aiohttp_cors
import ssl
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global variables to store extracted files and connections
extracted_files = {}
current_firmware_path = None
active_connections = {}  # Store active SSE connections

def resolve_file_path(file_id: str) -> str:
    """Resolve a file ID to its actual file path."""
    if file_id.startswith("download_"):
        # Extract filename from file ID
        filename = file_id.replace("download_", "")
        
        # Search in downloads directory
        download_dir = Path("downloads")
        if download_dir.exists():
            for file_path in download_dir.glob("*"):
                if file_path.is_file():
                    # Check if this file matches the filename
                    if file_path.name == filename:
                        return str(file_path.absolute())
    return file_id

def get_tools_definition():
    """Get the complete tools definition for MCP responses."""
    return {
        "update_firmware": {
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
        "decompress_file": {
            "description": "Recursively decompress a file until all files are in uncompressed format",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file to decompress or file ID"
                    }
                },
                "required": ["file_path"]
            }
        },
        "extract_with_binwalk": {
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
        "extract_squashfs": {
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
        "find_hardcoded_password": {
            "description": "Find hardcoded passwords in /etc/passwd and /etc/shadow files to identify security concerns",
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
        "crack_md5_password": {
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
        },
        "download_file": {
            "description": "Download a file from the internet to the MCP server",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL of the file to download"
                    },
                    "filename": {
                        "type": "string",
                        "description": "Optional custom filename for the downloaded file"
                    }
                },
                "required": ["url"]
            }
        },
        "list_local_files": {
            "description": "List all uploaded and downloaded files currently stored on the MCP server",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "show_details": {
                        "type": "boolean",
                        "description": "Whether to show detailed file information (default: true)"
                    }
                },
                "required": []
            }
        },
        "find_squashfs_format": {
            "description": "Find SquashFS filesystem format using the 'file' command",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file to analyze or file ID"
                    }
                },
                "required": ["file_path"]
            }
        }
    }

# Create a simple notification options object
class SimpleNotificationOptions:
    def __init__(self):
        self.tools_changed = False



async def update_firmware(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Upload and update firmware (.bin file)."""
    global current_firmware_path
    
    firmware_path = arguments.get("firmware_path")
    
    # Resolve file ID to actual path
    firmware_path = resolve_file_path(firmware_path)
    
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

async def decompress_file(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively decompress a file until all files are in uncompressed format.
    
    Args:
        file_path: Path to the file to decompress or file ID
    """
    file_path = arguments.get("file_path")
    
    # Resolve file ID to actual path
    file_path = resolve_file_path(file_path)
    
    if not file_path or not os.path.exists(file_path):
        return {"error": f"File not found at {file_path}"}
    
    try:
        # Create decompressed directory if it doesn't exist
        decompressed_dir = Path("decompressed")
        decompressed_dir.mkdir(exist_ok=True)
        
        # Create a unique subdirectory for this extraction
        timestamp = int(time.time())
        extract_dir = decompressed_dir / f"decompress_{os.path.basename(file_path)}_{timestamp}"
        extract_dir.mkdir(exist_ok=True)
        
        extracted_files_list = []
        decompression_log = []
        
        def decompress_recursive(current_file, current_dir, depth=0):
            """Recursively decompress files."""
            if depth > 10:  # Prevent infinite recursion
                decompression_log.append(f"Max depth reached for {current_file}")
                return
            
            try:
                # Use python-magic to identify file type
                mime_type = magic.from_file(current_file, mime=True)
                magic_info = magic.from_file(current_file)
                
                decompression_log.append(f"Level {depth}: Analyzing {os.path.basename(current_file)}")
                decompression_log.append(f"  MIME: {mime_type}")
                decompression_log.append(f"  Magic: {magic_info}")
                
                # Check for compressed formats
                if mime_type in ["application/zip", "application/x-zip-compressed"]:
                    decompression_log.append(f"  Detected: ZIP Archive - Extracting...")
                    extract_dir = os.path.join(current_dir, f"extracted_{os.path.basename(current_file)}")
                    os.makedirs(extract_dir, exist_ok=True)
                    
                    with zipfile.ZipFile(current_file, 'r') as zip_ref:
                        zip_ref.extractall(extract_dir)
                    
                    # Process extracted files
                    for root, dirs, files in os.walk(extract_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            decompress_recursive(file_path, extract_dir, depth + 1)
                    
                    extracted_files_list.append(extract_dir)
                    
                elif mime_type in ["application/x-tar", "application/x-gtar"]:
                    decompression_log.append(f"  Detected: TAR Archive - Extracting...")
                    extract_dir = os.path.join(current_dir, f"extracted_{os.path.basename(current_file)}")
                    os.makedirs(extract_dir, exist_ok=True)
                    
                    import tarfile
                    with tarfile.open(current_file, 'r:*') as tar_ref:
                        tar_ref.extractall(extract_dir)
                    
                    # Process extracted files
                    for root, dirs, files in os.walk(extract_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            decompress_recursive(file_path, extract_dir, depth + 1)
                    
                    extracted_files_list.append(extract_dir)
                    
                elif mime_type in ["application/gzip", "application/x-gzip"]:
                    decompression_log.append(f"  Detected: GZIP Compressed - Extracting...")
                    import gzip
                    import shutil
                    
                    # Determine output filename
                    if current_file.endswith('.gz'):
                        output_file = current_file[:-3]
                    else:
                        output_file = current_file + '.decompressed'
                    
                    with gzip.open(current_file, 'rb') as f_in:
                        with open(output_file, 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    
                    decompress_recursive(output_file, current_dir, depth + 1)
                    
                elif mime_type in ["application/x-bzip2"]:
                    decompression_log.append(f"  Detected: BZIP2 Compressed - Extracting...")
                    import bz2
                    import shutil
                    
                    # Determine output filename
                    if current_file.endswith('.bz2'):
                        output_file = current_file[:-4]
                    else:
                        output_file = current_file + '.decompressed'
                    
                    with bz2.open(current_file, 'rb') as f_in:
                        with open(output_file, 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    
                    decompress_recursive(output_file, current_dir, depth + 1)
                    
                elif mime_type in ["application/x-7z-compressed"]:
                    decompression_log.append(f"  Detected: 7-Zip Archive - Extracting...")
                    extract_dir = os.path.join(current_dir, f"extracted_{os.path.basename(current_file)}")
                    os.makedirs(extract_dir, exist_ok=True)
                    
                    # Use 7z command if available
                    try:
                        result = subprocess.run(
                            ["7z", "x", current_file, f"-o{extract_dir}", "-y"],
                            capture_output=True,
                            text=True,
                            check=True
                        )
                        
                        # Process extracted files
                        for root, dirs, files in os.walk(extract_dir):
                            for file in files:
                                file_path = os.path.join(root, file)
                                decompress_recursive(file_path, extract_dir, depth + 1)
                        
                        extracted_files_list.append(extract_dir)
                    except (subprocess.CalledProcessError, FileNotFoundError):
                        decompression_log.append(f"  7z command not available, skipping 7z extraction")
                
                elif mime_type in ["application/x-rar"]:
                    decompression_log.append(f"  Detected: RAR Archive - Extracting...")
                    extract_dir = os.path.join(current_dir, f"extracted_{os.path.basename(current_file)}")
                    os.makedirs(extract_dir, exist_ok=True)
                    
                    # Use unrar command if available
                    try:
                        result = subprocess.run(
                            ["unrar", "x", current_file, extract_dir],
                            capture_output=True,
                            text=True,
                            check=True
                        )
                        
                        # Process extracted files
                        for root, dirs, files in os.walk(extract_dir):
                            for file in files:
                                file_path = os.path.join(root, file)
                                decompress_recursive(file_path, extract_dir, depth + 1)
                        
                        extracted_files_list.append(extract_dir)
                    except (subprocess.CalledProcessError, FileNotFoundError):
                        decompression_log.append(f"  unrar command not available, skipping RAR extraction")
                
                elif "squashfs" in magic_info.lower():
                    decompression_log.append(f"  Detected: SquashFS Filesystem - Use extract_squashfs tool")
                    # Don't auto-extract SquashFS, let user decide
                
                elif mime_type.startswith("text/"):
                    decompression_log.append(f"  Detected: Text File - Already decompressed")
                    # Text files are already decompressed
                
                elif mime_type in ["application/octet-stream", "application/x-executable"]:
                    decompression_log.append(f"  Detected: Binary File - Use extract_with_binwalk tool")
                    # Binary files need binwalk analysis
                
                else:
                    decompression_log.append(f"  Detected: Unknown format - Skipping")
                
            except Exception as e:
                decompression_log.append(f"  Error processing {current_file}: {str(e)}")
        
        # Start recursive decompression
        decompress_recursive(file_path, extract_dir)
        
        # Collect final results
        final_files = []
        for root, dirs, files in os.walk(extract_dir):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    mime_type = magic.from_file(file_path, mime=True)
                    magic_info = magic.from_file(file_path)
                    final_files.append({
                        "path": file_path,
                        "name": file,
                        "mime_type": mime_type,
                        "magic_info": magic_info,
                        "size": os.path.getsize(file_path)
                    })
                except Exception as e:
                    final_files.append({
                        "path": file_path,
                        "name": file,
                        "error": str(e)
                    })
        
        result = {
            "original_file": file_path,
            "extraction_directory": str(extract_dir),
            "decompression_log": decompression_log,
            "final_files": final_files,
            "total_files": len(final_files),
            "extracted_directories": extracted_files_list
        }
        
        return result
        
    except Exception as e:
        return {"error": f"Error decompressing file: {str(e)}"}

async def extract_with_binwalk(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Use binwalk to recursively extract files from binary."""
    binary_path = arguments.get("binary_path")
    
    # Resolve file ID to actual path
    binary_path = resolve_file_path(binary_path)
    
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
                "next_step": f"Use find_hardcoded_password tool with path: {extract_dir}"
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
    
    # Resolve file ID to actual path
    squashfs_path = resolve_file_path(squashfs_path)
    
    if not squashfs_path or not os.path.exists(squashfs_path):
        return {
            "error": f"SquashFS file not found at {squashfs_path}"
        }
    
    # Create extracted_squashfs directory if it doesn't exist
    extracted_squashfs_dir = Path("extracted_squashfs")
    extracted_squashfs_dir.mkdir(exist_ok=True)
    
    # Create a unique subdirectory for this extraction
    timestamp = int(time.time())
    extract_dir = extracted_squashfs_dir / f"squashfs_extract_{os.path.basename(squashfs_path)}_{timestamp}"
    extract_dir.mkdir(exist_ok=True)
    
    try:
        # Run unsquashfs extraction with sudo to handle device files
        result = subprocess.run(
            ["unsquashfs", "-d", str(extract_dir), "-no-progress", squashfs_path],
            capture_output=True,
            text=True
        )
         
    except Exception as e:
        return {
            "error": f"Error during SquashFS extraction: {str(e)}"
        }

async def find_hardcoded_password(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Find hardcoded passwords in /etc/passwd and /etc/shadow files to identify security concerns."""
    extracted_path = arguments.get("extracted_path")
    
    if not extracted_path or not os.path.exists(extracted_path):
        return {
            "error": f"Extracted path not found at {extracted_path}"
        }
    
    passwd_files = []
    shadow_files = []
    security_issues = []
    
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
        "security_issues": [],
        "total_passwd": len(passwd_files),
        "total_shadow": len(shadow_files),
        "security_summary": {
            "critical_issues": 0,
            "high_issues": 0,
            "medium_issues": 0,
            "low_issues": 0
        }
    }
    
    # Process passwd files for security analysis
    for passwd_file in passwd_files:
        file_info = {
            "path": passwd_file,
            "content": [],
            "security_analysis": [],
            "users_with_passwords": [],
            "default_accounts": []
        }
        
        try:
            # Use sudo to read file with elevated permissions
            subprocess_result = subprocess.run(
                ["cat", passwd_file],
                capture_output=True,
                text=True
            )
            if subprocess_result.returncode != 0:
                file_info["error"] = f"Failed to read file: {subprocess_result.stderr}"
                result["passwd_files"].append(file_info)
                continue
            content = subprocess_result.stdout
            lines = content.split('\n')
            file_info["total_lines"] = len(lines)
            
            # Analyze each line for security issues
            for i, line in enumerate(lines[:10]):  # Analyze first 10 lines
                if line.strip() and not line.startswith('#'):
                    parts = line.split(':')
                    if len(parts) >= 7:
                            username = parts[0]
                            password_field = parts[1]
                            uid = parts[2]
                            gid = parts[3]
                            comment = parts[4]
                            home_dir = parts[5]
                            shell = parts[6]
                            
                            # Security analysis
                            issues = []
                            
                            # Check for users with passwords in passwd file (security risk)
                            if password_field != 'x' and password_field != '*':
                                issues.append("CRITICAL: User has password in /etc/passwd instead of /etc/shadow")
                                file_info["users_with_passwords"].append(username)
                                result["security_summary"]["critical_issues"] += 1
                            
                            # Check for default/weak accounts
                            default_accounts = ['root', 'admin', 'user', 'guest', 'test', 'demo']
                            if username.lower() in default_accounts:
                                issues.append("HIGH: Default account detected")
                                file_info["default_accounts"].append(username)
                                result["security_summary"]["high_issues"] += 1
                            
                            # Check for root UID (0)
                            if uid == '0' and username != 'root':
                                issues.append("CRITICAL: Non-root user with UID 0 (root privileges)")
                                result["security_summary"]["critical_issues"] += 1
                            
                            # Check for shell access
                            if shell not in ['/bin/false', '/usr/sbin/nologin', '/sbin/nologin']:
                                issues.append("MEDIUM: User has shell access")
                                result["security_summary"]["medium_issues"] += 1
                            
                            if issues:
                                file_info["security_analysis"].append({
                                    "line": i + 1,
                                    "username": username,
                                    "issues": issues
                                })
                            
                            file_info["content"].append(line)
                
        except Exception as e:
            file_info["error"] = str(e)
        
        result["passwd_files"].append(file_info)
    
    # Process shadow files for security analysis
    for shadow_file in shadow_files:
        file_info = {
            "path": shadow_file,
            "content": [],
            "security_analysis": [],
            "weak_passwords": [],
            "empty_passwords": []
        }
        
        try:
            # Use sudo to read file with elevated permissions
            subprocess_result = subprocess.run(
                ["cat", shadow_file],
                capture_output=True,
                text=True
            )
            if subprocess_result.returncode != 0:
                file_info["error"] = f"Failed to read file: {subprocess_result.stderr}"
                result["shadow_files"].append(file_info)
                continue
            content = subprocess_result.stdout
            lines = content.split('\n')
            file_info["total_lines"] = len(lines)
            
            # Analyze each line for security issues
            for i, line in enumerate(lines[:10]):  # Analyze first 10 lines
                if line.strip() and not line.startswith('#'):
                    parts = line.split(':')
                    if len(parts) >= 2:
                            username = parts[0]
                            password_hash = parts[1]
                            
                            # Security analysis
                            issues = []
                            
                            # Check for empty passwords
                            if password_hash == '':
                                issues.append("CRITICAL: Empty password detected")
                                file_info["empty_passwords"].append(username)
                                result["security_summary"]["critical_issues"] += 1
                            
                            # Check for weak password patterns
                            weak_patterns = [
                                '$1$',  # MD5
                                '$2a$', # Blowfish
                                '$2b$', # Blowfish
                                '$2y$', # Blowfish
                                '$5$',  # SHA-256
                                '$6$'   # SHA-512
                            ]
                            
                            if any(pattern in password_hash for pattern in weak_patterns):
                                issues.append("MEDIUM: Weak password hash algorithm detected")
                                file_info["weak_passwords"].append(username)
                                result["security_summary"]["medium_issues"] += 1
                            
                            # Check for locked accounts
                            if password_hash in ['*', '!']:
                                issues.append("LOW: Account is locked (good security practice)")
                                result["security_summary"]["low_issues"] += 1
                            
                            if issues:
                                file_info["security_analysis"].append({
                                    "line": i + 1,
                                    "username": username,
                                    "issues": issues
                                })
                            
                            file_info["content"].append(line)
                
        except Exception as e:
            file_info["error"] = str(e)
        
        result["shadow_files"].append(file_info)
    
    # Generate security summary
    total_issues = (result["security_summary"]["critical_issues"] + 
                   result["security_summary"]["high_issues"] + 
                   result["security_summary"]["medium_issues"] + 
                   result["security_summary"]["low_issues"])
    
    if total_issues > 0:
        result["security_issues"].append(f"Found {total_issues} security issues:")
        result["security_issues"].append(f"- {result['security_summary']['critical_issues']} Critical issues")
        result["security_issues"].append(f"- {result['security_summary']['high_issues']} High severity issues")
        result["security_issues"].append(f"- {result['security_summary']['medium_issues']} Medium severity issues")
        result["security_issues"].append(f"- {result['security_summary']['low_issues']} Low severity issues")
        
        if result["security_summary"]["critical_issues"] > 0:
            result["security_issues"].append("🚨 CRITICAL: Immediate action required!")
        if result["security_summary"]["high_issues"] > 0:
            result["security_issues"].append("⚠️ HIGH: Security review recommended!")
    else:
        result["security_issues"].append("✅ No obvious security issues found in password files")
    
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

async def download_file(arguments: Dict[str, Any]) -> str:
    """Download a file from the internet to the MCP server.
    
    Args:
        url: URL of the file to download
        filename: Optional custom filename for the downloaded file
    """
    url = arguments.get("url")
    custom_filename = arguments.get("filename")
    
    if not url:
        return "Error: URL is required"
    
    try:
        # Validate URL
        parsed_url = urllib.parse.urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            return "Error: Invalid URL format"
        
        # Create downloads directory if it doesn't exist
        download_dir = Path("downloads")
        download_dir.mkdir(exist_ok=True)
        
        # Get filename from URL if not provided
        if not custom_filename:
            custom_filename = os.path.basename(parsed_url.path)
            if not custom_filename or '.' not in custom_filename:
                custom_filename = f"downloaded_file_{int(asyncio.get_event_loop().time())}"
        
        # Create unique filename
        file_ext = Path(custom_filename).suffix
        if not file_ext:
            file_ext = ""
        unique_filename = f"{hashlib.md5(custom_filename.encode()).hexdigest()[:8]}_{int(asyncio.get_event_loop().time())}{file_ext}"
        file_path = download_dir / unique_filename
        
        # Download file
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status != 200:
                    return f"Error: Failed to download file. HTTP status: {response.status}"
                
                # Get content type and size
                content_type = response.headers.get('content-type', 'application/octet-stream')
                content_length = response.headers.get('content-length')
                
                # Download content
                content = await response.read()
                
                # Save file
                with open(file_path, 'wb') as f:
                    f.write(content)
                
                # Get file size
                file_size = os.path.getsize(file_path)
                
                # File is saved to filesystem, no need to store metadata in memory
                
                result = f"Success: File downloaded successfully!\n"
                result += f"Original URL: {url}\n"
                result += f"Saved as: {custom_filename}\n"
                result += f"File path: {file_path}\n"
                result += f"File size: {file_size} bytes\n"
                result += f"Content type: {content_type}\n"
                result += f"File ID: download_{file_path.name}\n\n"
                result += f"Next step: Use decompress_file tool with file ID: download_{file_path.name}"
                
                return result
                
    except Exception as e:
        return f"Error downloading file: {str(e)}"

async def list_local_files(arguments: Dict[str, Any]) -> str:
    """List all downloaded files currently stored on the MCP server.
    
    Args:
        show_details: Whether to show detailed file information (default: true)
    """
    show_details = arguments.get("show_details", True)
    
    try:
        # Read directly from downloads directory
        download_dir = Path("downloads")
        if not download_dir.exists():
            return "No files currently stored on the server."
        
        files = list(download_dir.glob("*"))
        if not files:
            return "No files currently stored on the server."
        
        result = f"Found {len(files)} file(s) on the server:\n\n"
        
        for i, file_path in enumerate(files, 1):
            if file_path.is_file():
                # Extract original filename from the stored filename
                stored_name = file_path.name
                # Try to extract original name from the hash prefix
                if '_' in stored_name:
                    original_name = stored_name.split('_', 1)[1]
                else:
                    original_name = stored_name
                
                file_size = file_path.stat().st_size
                file_time = datetime.fromtimestamp(file_path.stat().st_mtime)
                
                result += f"File {i}:\n"
                result += f"  Name: {original_name}\n"
                result += f"  ID: download_{original_name}\n"
                result += f"  Size: {file_size} bytes\n"
                result += f"  Source: download\n"
                
                if show_details:
                    result += f"  Path: {file_path.absolute()}\n"
                    result += f"  Modified time: {file_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                
                result += "\n"
        
        result += "Usage:\n"
        result += "- Use file IDs (e.g., 'download_filename') in other tools\n"
        result += "- Example: decompress_file with file_path: 'download_myfile.zip'\n"
        
        return result
        
    except Exception as e:
        return f"Error listing files: {str(e)}"

async def find_squashfs_format(arguments: Dict[str, Any]) -> str:
    """Find SquashFS filesystem format using the 'file' command.
    
    Args:
        file_path: Path to the file to analyze or file ID
    """
    file_path = arguments.get("file_path")
    
    # Resolve file ID to actual path
    file_path = resolve_file_path(file_path)
    
    if not file_path or not os.path.exists(file_path):
        return f"Error: File not found at {file_path}"
    
    try:
        # Use the 'file' command to analyze the file
        result = subprocess.run(
            ["file", file_path],
            capture_output=True,
            text=True,
            check=True
        )
        
        file_output = result.stdout.strip()
        
        # Check if it contains SquashFS information
        if "squashfs" in file_output.lower():
            result_text = f"✅ SquashFS filesystem detected!\n\n"
            result_text += f"File: {file_path}\n"
            result_text += f"File command output: {file_output}\n\n"
            result_text += f"Next step: Use extract_squashfs tool to extract the filesystem"
        else:
            result_text = f"❌ No SquashFS filesystem detected.\n\n"
            result_text += f"File: {file_path}\n"
            result_text += f"File command output: {file_output}\n\n"
            result_text += f"Note: This file does not appear to be a SquashFS filesystem."
        
        return result_text
        
    except subprocess.CalledProcessError as e:
        return f"Error running 'file' command: {e.stderr}"
    except Exception as e:
        return f"Error analyzing file: {str(e)}"

async def handle_uploaded_files(request):
    """Get list of downloaded files."""
    try:
        files_list = []
        
        # Read directly from downloads directory
        download_dir = Path("downloads")
        if download_dir.exists():
            for file_path in download_dir.glob("*"):
                if file_path.is_file():
                    # Extract original filename from the stored filename
                    stored_name = file_path.name
                    if '_' in stored_name:
                        original_name = stored_name.split('_', 1)[1]
                    else:
                        original_name = stored_name
                    
                    files_list.append({
                        "id": f"download_{original_name}",
                        "name": original_name,
                        "path": str(file_path.absolute()),
                        "size": file_path.stat().st_size,
                        "modified_time": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
                        "source": "download"
                    })
        
        return web.json_response({
            "success": True,
            "files": files_list
        })
    except Exception as e:
        return web.json_response({"error": str(e)})

# SSE (Server-Sent Events) handlers for MCP protocol
async def handle_sse_connection(request):
    """Handle SSE connection for MCP protocol."""
    response = web.StreamResponse(
        status=200,
        headers={
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Cache-Control'
        }
    )
    
    await response.prepare(request)
    
    # Generate unique connection ID
    connection_id = str(uuid.uuid4())
    active_connections[connection_id] = response
    
    try:
        # Send initial connection event
        await response.write(f"data: {json.dumps({'type': 'connected', 'connection_id': connection_id})}\n\n".encode())
        
        # Send MCP server capabilities
        capabilities = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": get_tools_definition()
                },
                "serverInfo": {
                    "name": "firmware-analyzer-mcp-sse",
                    "version": "1.0.0"
                }
            }
        }
        await response.write(f"data: {json.dumps(capabilities)}\n\n".encode())
        
        # Send ready notification
        ready_notification = {
            "jsonrpc": "2.0",
            "method": "notifications/ready",
            "params": {}
        }
        await response.write(f"data: {json.dumps(ready_notification)}\n\n".encode())
        
        # Keep connection alive and handle MCP requests
        while True:
            await asyncio.sleep(1)
            # Send heartbeat
            await response.write(f"data: {json.dumps({'type': 'heartbeat', 'timestamp': datetime.now().isoformat()})}\n\n".encode())
            
    except asyncio.CancelledError:
        logger.info(f"SSE connection {connection_id} cancelled")
    except Exception as e:
        logger.error(f"SSE connection error: {e}")
    finally:
        if connection_id in active_connections:
            del active_connections[connection_id]
        await response.write_eof()

async def handle_mcp_sse_request(request):
    """Handle MCP protocol requests via SSE."""
    try:
        data = await request.json()
        
        method = data.get("method")
        params = data.get("params", {})
        request_id = data.get("id")
        
        # Get connection ID from headers or generate one
        connection_id = request.headers.get("X-Connection-ID")
        if not connection_id:
            connection_id = str(uuid.uuid4())
        
        # Handle different MCP methods
        if method == "initialize":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "firmware-analyzer-mcp-sse",
                        "version": "1.0.0"
                    }
                }
            }
            
        elif method == "tools/list":
            # Convert tools definition to list format for tools/list
            tools_def = get_tools_definition()
            tools = []
            for name, definition in tools_def.items():
                tools.append({
                    "name": name,
                    "description": definition["description"],
                    "inputSchema": definition["inputSchema"]
                })
            
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "tools": tools
                }
            }
            
        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            
            # Map tool calls to our functions
            tool_handlers = {
                "update_firmware": update_firmware,
                "decompress_file": decompress_file,
                "extract_with_binwalk": extract_with_binwalk,
                "extract_squashfs": extract_squashfs,
                "find_hardcoded_password": find_hardcoded_password,
                "crack_md5_password": crack_md5_password,
                "download_file": download_file,
                "list_local_files": list_local_files,
                "find_squashfs_format": find_squashfs_format
            }
            
            if tool_name in tool_handlers:
                result = await tool_handlers[tool_name](arguments)
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
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
                    "id": request_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {tool_name}"
                    }
                }
        else:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}"
                }
            }
        
        # Send response via SSE if connection exists
        if connection_id in active_connections:
            sse_response = active_connections[connection_id]
            await sse_response.write(f"data: {json.dumps(response)}\n\n".encode())
        
        # For SSE endpoint, return SSE content type
        if request.path == '/sse':
            return web.Response(
                text=f"data: {json.dumps(response)}\n\n",
                content_type='text/event-stream',
                headers={
                    'Cache-Control': 'no-cache',
                    'Connection': 'keep-alive',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Headers': '*'
                }
            )
        
        return web.json_response(response)
        
    except Exception as e:
        error_response = {
            "jsonrpc": "2.0",
            "id": data.get("id") if 'data' in locals() else None,
            "error": {
                "code": -32603,
                "message": f"Internal error: {str(e)}"
            }
        }
        return web.json_response(error_response)



# HTTP route handlers
async def handle_index(request):
    """Handle root URI - serve JSON info or handle MCP requests."""
    
    # Check if this is an MCP request
    if request.method == "POST":
        try:
            data = await request.json()
            method = data.get("method")
            params = data.get("params", {})
            request_id = data.get("id")
            
            if method == "initialize":
                # Handle MCP initialize request
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": get_tools_definition()
                        },
                        "serverInfo": {
                            "name": "firmware-analyzer-mcp-sse",
                            "version": "1.0.0"
                        }
                    }
                }
                return web.json_response(response)
                
            elif method == "tools/list":
                # Convert tools definition to list format for tools/list
                tools_def = get_tools_definition()
                tools = []
                for name, definition in tools_def.items():
                    tools.append({
                        "name": name,
                        "description": definition["description"],
                        "inputSchema": definition["inputSchema"]
                    })
                
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "tools": tools
                    }
                }
                return web.json_response(response)
                
            elif method == "tools/call":
                tool_name = params.get("name")
                arguments = params.get("arguments", {})
                
                # Map tool calls to our functions
                tool_handlers = {
                    "update_firmware": update_firmware,
                    "decompress_file": decompress_file,
                    "extract_with_binwalk": extract_with_binwalk,
                    "extract_squashfs": extract_squashfs,
                    "find_hardcoded_password": find_hardcoded_password,
                    "crack_md5_password": crack_md5_password,
                    "download_file": download_file,
                    "list_local_files": list_local_files,
                    "find_squashfs_format": find_squashfs_format
                }
                
                if tool_name in tool_handlers:
                    result = await tool_handlers[tool_name](arguments)
                    response = {
                        "jsonrpc": "2.0",
                        "id": request_id,
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
                        "id": request_id,
                        "error": {
                            "code": -32601,
                            "message": f"Method not found: {tool_name}"
                        }
                    }
                return web.json_response(response)
                
            else:
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {method}"
                    }
                }
                return web.json_response(response)
                
        except Exception as e:
            error_response = {
                "jsonrpc": "2.0",
                "id": data.get("id") if 'data' in locals() else None,
                "error": {
                    "code": -32603,
                    "message": f"Internal error: {str(e)}"
                }
            }
            return web.json_response(error_response)
    
    # JSON info for GET requests
    info_response = {
        "server": "Firmware Analyzer MCP Server (SSE)",
        "version": "1.0.0",
        "endpoints": {
            "GET /": "This info page (JSON)",
            "POST /": "MCP requests (initialize, tools/list, tools/call)",
            "GET /sse": "SSE connection",
            "POST /sse": "MCP requests via SSE",
            "POST /mcp": "Alternative MCP endpoint",
            "GET /api/uploaded-files": "List downloaded files"
        },
        "tools": [
            "update_firmware",
            "decompress_file", 
            "extract_with_binwalk",
            "extract_squashfs",
            "find_hardcoded_password",
            "crack_md5_password",
            "download_file",
            "list_local_files",
            "find_squashfs_format"
        ],
        "status": "running"
    }
    return web.json_response(info_response)

async def handle_update_firmware(request):
    """Handle update_firmware tool call."""
    try:
        data = await request.json()
        result = await update_firmware(data)
        return web.json_response(result)
    except Exception as e:
        return web.json_response({"error": str(e)})

async def handle_decompress_file(request):
    """Handle decompress_file tool call."""
    try:
        data = await request.json()
        result = await decompress_file(data)
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

async def handle_find_hardcoded_password(request):
    """Handle find_hardcoded_password tool call."""
    try:
        data = await request.json()
        result = await find_hardcoded_password(data)
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
    # Convert tools definition to list format for tools/list
    tools_def = get_tools_definition()
    tools = []
    for name, definition in tools_def.items():
        tools.append({
            "name": name,
            "description": definition["description"],
            "inputSchema": definition["inputSchema"]
        })
    
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
    app.router.add_post('/', handle_index)  # Handle MCP initialize at root
    app.router.add_get('/sse', handle_sse_connection)
    app.router.add_post('/sse', handle_mcp_sse_request)  # Handle MCP requests via SSE
    app.router.add_post('/mcp', handle_mcp_sse_request)  # Alternative MCP endpoint
    app.router.add_get('/api/uploaded-files', handle_uploaded_files)
    app.router.add_get('/api/tools/list', handle_tools_list)
    app.router.add_post('/api/update_firmware', handle_update_firmware)
    app.router.add_post('/api/decompress_file', handle_decompress_file)
    app.router.add_post('/api/extract_with_binwalk', handle_extract_with_binwalk)
    app.router.add_post('/api/extract_squashfs', handle_extract_squashfs)
    app.router.add_post('/api/find_hardcoded_password', handle_find_hardcoded_password)
    app.router.add_post('/api/crack_md5_password', handle_crack_md5_password)
    
    # Add CORS to all routes
    for route in list(app.router.routes()):
        cors.add(route)
    
    return app

def main():
    """Main function to run the SSE MCP server."""
    import argparse
    
    parser = argparse.ArgumentParser(description='SSE-based MCP Firmware Analyzer Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8083, help='Port to bind to (default: 8083)')
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
            logger.info(f"SSL SSE MCP Server started on {args.host}:{args.port}")
        else:
            web.run_app(app, host=args.host, port=args.port)
            logger.info(f"SSE MCP Server started on {args.host}:{args.port}")
            
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")

if __name__ == "__main__":
    main() 