# 📡 stdio-based MCP Server

This directory contains the **stdio-based MCP (Model Context Protocol) server** implementation for firmware analysis and password extraction.

## 📁 **Files**

- **`firmware_analyzer_mcp.py`** - Main stdio MCP server implementation
- **`mcp-config.json`** - MCP client configuration for stdio server
- **`README.md`** - Original comprehensive documentation
- **`direct_firmware_analyzer.py`** - Direct function caller (bypasses MCP protocol)
- **`crack_passwords.py`** - Standalone password cracking utility
- **`mcp_client.py`** - Python MCP client implementation
- **`mcp_client_simple.py`** - Simplified MCP client using mcp.client library
- **`test_mcp_simple.py`** - Test script for raw JSON-RPC communication

## 🚀 **Quick Start**

```bash
# Start the stdio MCP server
python3 firmware_analyzer_mcp.py

# Test with direct function calls
python3 direct_firmware_analyzer.py

# Test password cracking
python3 crack_passwords.py

# Test MCP client communication
python3 mcp_client.py
```

## 🔧 **Features**

- **Standard MCP Protocol** - Full compliance with MCP specification
- **stdio Transport** - Uses standard input/output for communication
- **6 Analysis Tools** - Complete firmware analysis workflow
- **Password Cracking** - MD5-crypt password cracking capabilities
- **Multiple Client Support** - Various client implementations for testing

## 📖 **Documentation**

See `README.md` for comprehensive documentation including:
- Installation instructions
- Usage examples
- Tool descriptions
- Troubleshooting guide
- Security considerations

## 🔗 **Related**

- **Network Version**: `../network/`
- **HTTP Version**: `../streaming-http/` 