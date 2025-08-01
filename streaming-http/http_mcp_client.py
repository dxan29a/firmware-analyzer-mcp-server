#!/usr/bin/env python3
"""
HTTP Client for Firmware Analyzer MCP Server
Simple client to test the HTTP-based MCP server functionality.
"""

import asyncio
import aiohttp
import json
import logging
import argparse
from typing import Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class HTTPMCPClient:
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call a tool on the MCP server."""
        url = f"{self.base_url}/api/{tool_name}"
        
        try:
            async with self.session.post(url, json=arguments) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    error_text = await response.text()
                    return {"error": f"HTTP {response.status}: {error_text}"}
        except Exception as e:
            return {"error": f"Request failed: {str(e)}"}
    
    async def get_tools_list(self) -> Dict[str, Any]:
        """Get the list of available tools."""
        url = f"{self.base_url}/api/tools/list"
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    error_text = await response.text()
                    return {"error": f"HTTP {response.status}: {error_text}"}
        except Exception as e:
            return {"error": f"Request failed: {str(e)}"}

async def test_firmware_analysis(firmware_path: str, server_url: str = "http://localhost:8080"):
    """Test the complete firmware analysis workflow."""
    logger.info(f"Starting firmware analysis for: {firmware_path}")
    logger.info(f"Server URL: {server_url}")
    
    async with HTTPMCPClient(server_url) as client:
        # Step 1: Update firmware
        logger.info("Step 1: Updating firmware...")
        result = await client.call_tool("update_firmware", {"firmware_path": firmware_path})
        print(f"Update Firmware Result: {json.dumps(result, indent=2)}")
        
        if "error" in result:
            logger.error(f"Failed to update firmware: {result['error']}")
            return
        
        # Step 2: Identify file format
        logger.info("Step 2: Identifying file format...")
        result = await client.call_tool("identify_file_format", {"file_path": firmware_path})
        print(f"File Format Result: {json.dumps(result, indent=2)}")
        
        if "error" in result:
            logger.error(f"Failed to identify file format: {result['error']}")
            return
        
        # Step 3: Extract with binwalk if it's a binary
        if result.get("detected_format") == "Binary":
            logger.info("Step 3: Extracting with binwalk...")
            result = await client.call_tool("extract_with_binwalk", {"binary_path": firmware_path})
            print(f"Binwalk Result: {json.dumps(result, indent=2)}")
            
            if "error" in result:
                logger.error(f"Failed to extract with binwalk: {result['error']}")
                return
            
            # Step 4: Find password files in extracted directory
            if "extraction_directory" in result:
                logger.info("Step 4: Finding password files...")
                result = await client.call_tool("find_password_files", {
                    "extracted_path": result["extraction_directory"]
                })
                print(f"Password Files Result: {json.dumps(result, indent=2)}")
                
                # Step 5: Try to crack any found passwords
                if result.get("shadow_files"):
                    for shadow_file in result["shadow_files"]:
                        if "content" in shadow_file:
                            for line in shadow_file["content"]:
                                if line and ":" in line:
                                    parts = line.split(":")
                                    if len(parts) >= 2 and parts[1] != "*" * 20:
                                        # This is a real hash, try to crack it
                                        logger.info(f"Step 5: Attempting to crack password hash...")
                                        crack_result = await client.call_tool("crack_md5_password", {
                                            "password_hash": parts[1]
                                        })
                                        print(f"Password Cracking Result: {json.dumps(crack_result, indent=2)}")
        
        # Step 6: If it's a ZIP file, search for SquashFS files
        elif result.get("detected_format") == "ZIP" and "extracted_path" in result:
            logger.info("Step 6: Searching for SquashFS files in extracted ZIP...")
            
            # This would require additional logic to find SquashFS files
            # For now, just search for password files in the extracted directory
            result = await client.call_tool("find_password_files", {
                "extracted_path": result["extracted_path"]
            })
            print(f"Password Files Result: {json.dumps(result, indent=2)}")

async def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='HTTP MCP Client for Firmware Analysis')
    parser.add_argument('--firmware', required=True, help='Path to firmware file')
    parser.add_argument('--server', default='http://localhost:8080', help='Server URL')
    parser.add_argument('--test-tools', action='store_true', help='Test tools list endpoint')
    
    args = parser.parse_args()
    
    async with HTTPMCPClient(args.server) as client:
        if args.test_tools:
            logger.info("Testing tools list endpoint...")
            result = await client.get_tools_list()
            print(f"Tools List: {json.dumps(result, indent=2)}")
        else:
            await test_firmware_analysis(args.firmware, args.server)

if __name__ == "__main__":
    asyncio.run(main()) 