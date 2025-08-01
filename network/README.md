# 🌐 Network-based MCP Server

This directory contains the **TCP-based MCP (Model Context Protocol) server** implementation for firmware analysis and password extraction.

## 📁 **Files**

- **`firmware_analyzer_mcp_network.py`** - Main TCP network MCP server implementation
- **`network_mcp_client.py`** - Python TCP client for network server
- **`mcp-network-config.json`** - MCP client configuration for network server
- **`README_NETWORK.md`** - Comprehensive network server documentation
- **`test_network_connection.py`** - Test script for network JSON-RPC communication

## 🚀 **Quick Start**

```bash
# Start the network MCP server
python3 firmware_analyzer_mcp_network.py --port 8080

# Test with network client
python3 network_mcp_client.py --firmware /path/to/firmware.bin --server localhost --port 8080

# Test basic network connection
python3 test_network_connection.py
```

## 🔧 **Features**

- **TCP Network Transport** - Uses TCP sockets for client-server communication
- **Multi-Client Support** - Handles multiple concurrent client connections
- **SSL/TLS Support** - Optional encryption for secure communications
- **6 Analysis Tools** - Complete firmware analysis workflow
- **Async I/O** - Non-blocking operations for better performance
- **JSON-RPC Protocol** - Standard MCP protocol over TCP

## 📖 **Documentation**

See `README_NETWORK.md` for comprehensive documentation including:
- Network architecture overview
- Server and client options
- SSL/TLS configuration
- Usage examples
- Troubleshooting guide
- Security considerations

## 🔗 **Related**

- **stdio Version**: `../stdio/`
- **HTTP Version**: `../streaming-http/` 