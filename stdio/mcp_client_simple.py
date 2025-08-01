#!/usr/bin/env python3
"""
Simple MCP Client using MCP Client Library
"""

import asyncio
import os
from mcp.client.stdio import stdio_client
from mcp.client.models import InitializationOptions

async def analyze_firmware_with_mcp(firmware_path: str):
    """Analyze firmware using MCP client library."""
    
    print(f"🔍 Starting firmware analysis for: {firmware_path}")
    print("=" * 60)
    
    # Check if firmware file exists
    if not os.path.exists(firmware_path):
        print(f"❌ Firmware file not found: {firmware_path}")
        return
    
    try:
        # Connect to the MCP server
        async with stdio_client("python3", ["firmware_analyzer_mcp.py"]) as (read, write):
            # Initialize the client
            await write.write_initialize(
                InitializationOptions(
                    protocol_version="2024-11-05",
                    capabilities={
                        "tools": {}
                    },
                    client_info={
                        "name": "firmware-analyzer-client",
                        "version": "1.0.0"
                    }
                )
            )
            
            # Read initialization response
            init_response = await read.read_initialize_response()
            print("✅ Server initialized successfully")
            
            # List tools
            tools_response = await write.write_list_tools()
            tools_result = await read.read_list_tools_response()
            
            print("\n📋 Available tools:")
            for tool in tools_result.tools:
                print(f"  - {tool.name}: {tool.description}")
            
            print("\n" + "=" * 60)
            
            # Step 1: Update firmware
            print("\n1️⃣ Updating firmware...")
            update_result = await write.write_call_tool("update_firmware", {
                "firmware_path": firmware_path
            })
            update_response = await read.read_call_tool_response()
            
            if update_response.content:
                for item in update_response.content:
                    if hasattr(item, 'text'):
                        print(item.text)
            
            # Step 2: Identify file format
            print("\n2️⃣ Identifying file format...")
            format_result = await write.write_call_tool("identify_file_format", {
                "file_path": firmware_path
            })
            format_response = await read.read_call_tool_response()
            
            if format_response.content:
                for item in format_response.content:
                    if hasattr(item, 'text'):
                        print(item.text)
            
            # Step 3: Extract with binwalk
            print("\n3️⃣ Extracting with binwalk...")
            binwalk_result = await write.write_call_tool("extract_with_binwalk", {
                "binary_path": firmware_path
            })
            binwalk_response = await read.read_call_tool_response()
            
            if binwalk_response.content:
                for item in binwalk_response.content:
                    if hasattr(item, 'text'):
                        text = item.text
                        print(text)
                        
                        # Extract the extraction directory path from the output
                        if "Extraction directory:" in text:
                            lines = text.split('\n')
                            for line in lines:
                                if "Extraction directory:" in line:
                                    extract_dir = line.split("Extraction directory:")[1].strip()
                                    print(f"\n📁 Found extraction directory: {extract_dir}")
                                    
                                    # Step 4: Find password files
                                    print("\n4️⃣ Searching for password files...")
                                    password_result = await write.write_call_tool("find_password_files", {
                                        "extracted_path": extract_dir
                                    })
                                    password_response = await read.read_call_tool_response()
                                    
                                    if password_response.content:
                                        for item in password_response.content:
                                            if hasattr(item, 'text'):
                                                print(item.text)
                                    
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
    
    print("🚀 Starting MCP Client for Firmware Analysis")
    print(f"📁 Target file: {firmware_path}")
    
    # Run the analysis
    asyncio.run(analyze_firmware_with_mcp(firmware_path))

if __name__ == "__main__":
    main() 