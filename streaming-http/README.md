# 🌐 Streaming HTTP-based MCP Server

This directory contains the **HTTP-based MCP (Model Context Protocol) server** implementation for firmware analysis and password extraction.

## 📁 **Files**

- **`firmware_analyzer_mcp_http.py`** - Main HTTP MCP server implementation
- **`http_mcp_client.py`** - Python HTTP client for web server
- **`README_HTTP.md`** - Comprehensive HTTP server documentation

## 🚀 **Quick Start**

```bash
# Start the HTTP MCP server
python3 firmware_analyzer_mcp_http.py --port 8080

# Open web interface in browser
xdg-open http://localhost:8080

# Test with HTTP client
python3 http_mcp_client.py --firmware /path/to/firmware.bin --server http://localhost:8080

# Test REST API
curl http://localhost:8080/api/tools/list
```

## 🔧 **Features**

- **HTTP/HTTPS Transport** - Uses HTTP protocol for client-server communication
- **Web Interface** - Built-in HTML5 UI for interactive use
- **REST API** - RESTful endpoints for all MCP tools
- **CORS Support** - Cross-origin requests for web applications
- **SSL/TLS Support** - Native HTTPS support for secure communications
- **6 Analysis Tools** - Complete firmware analysis workflow
- **Async I/O** - Non-blocking operations using aiohttp
- **JSON API** - Standard JSON request/response format

## 📖 **Documentation**

See `README_HTTP.md` for comprehensive documentation including:
- Web interface usage
- REST API reference
- Client examples (Python, JavaScript, curl)
- SSL/TLS configuration
- CORS setup
- Performance considerations
- Troubleshooting guide

## 🔗 **Related**

- **stdio Version**: `../stdio/`
- **Network Version**: `../network/` 