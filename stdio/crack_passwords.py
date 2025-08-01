#!/usr/bin/env python3
"""
Password Cracking Script
This script uses the MCP server to crack the password hashes found in the firmware.
"""

import asyncio
from firmware_analyzer_mcp import crack_md5_password

async def crack_firmware_passwords():
    """Crack the password hashes found in the firmware."""
    
    print("🔓 Cracking Firmware Passwords")
    print("=" * 50)
    
    # The password hash found in the firmware
    root_hash = "$1$hgPZ0Ht7$m34harz3OOVPSdlW5EjVQ."
    
    print(f"Root password hash: {root_hash}")
    print("\nAttempting to crack the password...")
    
    # Try to crack the password
    result = await crack_md5_password({
        "password_hash": root_hash
    })
    
    if result and result.content:
        for item in result.content:
            if hasattr(item, 'text'):
                print(item.text)
    
    print("\n" + "=" * 50)
    print("Password cracking completed!")

def main():
    """Main entry point."""
    asyncio.run(crack_firmware_passwords())

if __name__ == "__main__":
    main() 