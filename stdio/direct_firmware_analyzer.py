#!/usr/bin/env python3
"""
Direct Firmware Analyzer
This script directly calls the MCP server functions to analyze firmware files.
"""

import asyncio
import os
import tempfile
import shutil
from firmware_analyzer_mcp import (
    update_firmware, identify_file_format, extract_with_binwalk,
    extract_squashfs, find_password_files, crack_md5_password
)

async def analyze_firmware_direct(firmware_path: str):
    """Analyze firmware by directly calling the MCP server functions."""
    
    print(f"🔍 Starting firmware analysis for: {firmware_path}")
    print("=" * 60)
    
    # Check if firmware file exists
    if not os.path.exists(firmware_path):
        print(f"❌ Firmware file not found: {firmware_path}")
        return
    
    try:
        # Step 1: Update firmware
        print("\n1️⃣ Updating firmware...")
        update_result = await update_firmware({"firmware_path": firmware_path})
        if update_result and update_result.content:
            for item in update_result.content:
                if hasattr(item, 'text'):
                    print(item.text)
        
        # Step 2: Identify file format
        print("\n2️⃣ Identifying file format...")
        format_result = await identify_file_format({"file_path": firmware_path})
        if format_result and format_result.content:
            for item in format_result.content:
                if hasattr(item, 'text'):
                    print(item.text)
        
        # Step 3: Check if ZIP was extracted and analyze contents
        print("\n3️⃣ Analyzing extracted ZIP contents...")
        
        # Check if the ZIP was extracted (from step 2)
        zip_extract_dir = None
        if format_result and format_result.content:
            for item in format_result.content:
                if hasattr(item, 'text') and "ZIP extracted to:" in item.text:
                    lines = item.text.split('\n')
                    for line in lines:
                        if "ZIP extracted to:" in line:
                            zip_extract_dir = line.split("ZIP extracted to:")[1].strip()
                            print(f"📁 Found ZIP extraction directory: {zip_extract_dir}")
                            break
        
        if zip_extract_dir and os.path.exists(zip_extract_dir):
            # Step 4: Find password files in extracted ZIP
            print("\n4️⃣ Searching for password files in extracted ZIP...")
            password_result = await find_password_files({"extracted_path": zip_extract_dir})
            if password_result and password_result.content:
                for item in password_result.content:
                    if hasattr(item, 'text'):
                        print(item.text)
            
            # Step 5: Try binwalk on extracted files
            print("\n5️⃣ Running binwalk on extracted files...")
            for root, dirs, files in os.walk(zip_extract_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    print(f"🔍 Analyzing file: {file}")
                    
                    # Try binwalk on this file
                    binwalk_result = await extract_with_binwalk({"binary_path": file_path})
                    if binwalk_result and binwalk_result.content:
                        for item in binwalk_result.content:
                            if hasattr(item, 'text'):
                                text = item.text
                                if "Extraction directory:" in text:
                                    lines = text.split('\n')
                                    for line in lines:
                                        if "Extraction directory:" in line:
                                            extract_dir = line.split("Extraction directory:")[1].strip()
                                            print(f"📁 Found binwalk extraction directory: {extract_dir}")
                                            
                                            # Search for password files in binwalk extraction
                                            print(f"🔍 Searching for password files in {extract_dir}...")
                                            password_result = await find_password_files({"extracted_path": extract_dir})
                                            if password_result and password_result.content:
                                                for item in password_result.content:
                                                    if hasattr(item, 'text'):
                                                        print(item.text)
                                            
                                            # Step 6: Check for SquashFS files and extract them
                                            print(f"\n6️⃣ Checking for SquashFS files in {extract_dir}...")
                                            for root2, dirs2, files2 in os.walk(extract_dir):
                                                for file2 in files2:
                                                    file2_path = os.path.join(root2, file2)
                                                    # Check if it's a SquashFS file
                                                    if file2 == "root" or file2.endswith('.squashfs'):
                                                        print(f"🔍 Found potential SquashFS file: {file2}")
                                                        
                                                        # Try to extract SquashFS
                                                        squashfs_result = await extract_squashfs({"squashfs_path": file2_path})
                                                        if squashfs_result and squashfs_result.content:
                                                            for item in squashfs_result.content:
                                                                if hasattr(item, 'text'):
                                                                    text = item.text
                                                                    print(text)
                                                                    
                                                                    # Extract the SquashFS extraction directory
                                                                    if "Extraction directory:" in text:
                                                                        lines = text.split('\n')
                                                                        for line in lines:
                                                                            if "Extraction directory:" in line:
                                                                                squashfs_extract_dir = line.split("Extraction directory:")[1].strip()
                                                                                print(f"📁 Found SquashFS extraction directory: {squashfs_extract_dir}")
                                                                                
                                                                                # Search for password files in SquashFS extraction
                                                                                print(f"🔍 Searching for password files in SquashFS extraction...")
                                                                                password_result = await find_password_files({"extracted_path": squashfs_extract_dir})
                                                                                if password_result and password_result.content:
                                                                                    for item in password_result.content:
                                                                                        if hasattr(item, 'text'):
                                                                                            print(item.text)
                                                                                break
                                            break
                                    break
        
        print("\n" + "=" * 60)
        print("✅ Firmware analysis completed!")
        
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        import traceback
        traceback.print_exc()

def main():
    """Main entry point."""
    firmware_path = "/home/alan/Downloads/A8000RU_V7.1cu.643_B20200521.zip"
    
    if not os.path.exists(firmware_path):
        print(f"❌ Firmware file not found: {firmware_path}")
        print("Please make sure the file exists and the path is correct.")
        return
    
    print("🚀 Starting Direct Firmware Analyzer")
    print(f"📁 Target file: {firmware_path}")
    
    # Run the analysis
    asyncio.run(analyze_firmware_direct(firmware_path))

if __name__ == "__main__":
    main() 