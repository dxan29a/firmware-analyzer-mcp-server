# SSE-based MCP Server for Firmware Analysis

This directory contains a **Server-Sent Events (SSE)** based MCP server implementation that provides real-time communication for firmware analysis and password cracking tools.

## 🚀 Features

- **SSE (Server-Sent Events)** for real-time communication
- **Direct VS Code GitHub Copilot integration** via stdio bridge
- **All original firmware analysis tools**:
  - `update_firmware` - Upload and update firmware (.bin file)
  - `identify_file_format` - Identify file format and handle accordingly
  - `extract_with_binwalk` - Use binwalk to extract files from binary
  - `extract_squashfs` - Use unsquash tool to open Squashfs filesystem
  - `find_password_files` - Find /etc/passwd and /etc/shadow files
  - `crack_md5_password` - Try to crack MD5-crypt passwords
- **File upload functionality** with drag-and-drop web interface
- **REST API endpoints** for programmatic access
- **Web interface** with real-time SSE status

## 📁 Files

- `firmware_analyzer_mcp_sse.py` - Main SSE MCP server
- `sse_to_stdio_bridge.py` - Bridge to connect VS Code via stdio
- `mcp-config-sse.json` - VS Code MCP configuration
- `README.md` - This documentation

## 🛠️ Installation

1. **Install dependencies** (if not already installed):
   ```bash
   sudo apt-get install python3-aiohttp python3-aiohttp-cors python3-magic python3-passlib binwalk squashfs-tools
   ```

2. **Make scripts executable**:
   ```bash
   chmod +x firmware_analyzer_mcp_sse.py sse_to_stdio_bridge.py
   ```

## 🚀 Usage

### 1. Start the SSE Server

```bash
cd sse
python3 firmware_analyzer_mcp_sse.py --port 8083
```

The server will start on `http://localhost:8083` with:
- **Web interface**: `http://localhost:8083/`
- **SSE endpoint**: `http://localhost:8083/sse`
- **MCP endpoint**: `http://localhost:8083/mcp`
- **REST API**: `http://localhost:8083/api/*`

### 2. Connect VS Code GitHub Copilot

#### Option A: Use the provided configuration

Copy the MCP configuration to your VS Code workspace:

```bash
cp mcp-config-sse.json ~/.vscode/settings.json
```

#### Option B: Add to VS Code settings manually

Add this to your VS Code settings (`.vscode/settings.json`):

```json
{
    "mcpServers": {
        "firmware-analyzer-sse": {
            "command": "python3",
            "args": [
                "/home/alan/Repository/rock-firmware/sse/sse_to_stdio_bridge.py",
                "--url",
                "http://localhost:8083"
            ],
            "env": {}
        }
    }
}
```

#### Option C: Use environment variable

Set the MCP configuration via environment variable:

```bash
export VSCODE_MCP_SERVERS='{"firmware-analyzer-sse":{"command":"python3","args":["/home/alan/Repository/rock-firmware/sse/sse_to_stdio_bridge.py","--url","http://localhost:8083"],"env":{}}}'
```

### 3. Restart VS Code

After configuring, restart VS Code and GitHub Copilot should connect to the SSE server.

## 🔧 API Endpoints

### SSE Endpoints

- `GET /sse` - SSE connection for real-time events
- `POST /mcp` - MCP protocol requests

### REST API Endpoints

- `GET /` - Web interface
- `POST /api/upload` - File upload
- `GET /api/uploaded-files` - List uploaded files
- `GET /api/tools/list` - List available tools
- `POST /api/update_firmware` - Update firmware
- `POST /api/identify_file_format` - Identify file format
- `POST /api/extract_with_binwalk` - Extract with binwalk
- `POST /api/extract_squashfs` - Extract SquashFS
- `POST /api/find_password_files` - Find password files
- `POST /api/crack_md5_password` - Crack MD5 password

## 🔍 Testing

### Test SSE Connection

```bash
# Test SSE endpoint
curl -N http://localhost:8083/sse

# Test MCP initialize
curl -X POST http://localhost:8083/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}'

# Test tools list
curl -X POST http://localhost:8083/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}'
```

### Test File Upload

```bash
# Upload a firmware file
curl -X POST http://localhost:8083/api/upload \
  -F "file=@/path/to/your/firmware.bin"

# List uploaded files
curl http://localhost:8083/api/uploaded-files
```

### Test Tool Execution

```bash
# Test identify_file_format
curl -X POST http://localhost:8083/api/identify_file_format \
  -H "Content-Type: application/json" \
  -d '{"file_path": "/path/to/firmware.bin"}'

# Test crack_md5_password
curl -X POST http://localhost:8083/api/crack_md5_password \
  -H "Content-Type: application/json" \
  -d '{"password_hash": "$1$salt$hash"}'
```

## 🌐 Web Interface

Visit `http://localhost:8083/` to access the web interface with:

- **Real-time SSE status** indicator
- **Drag-and-drop file upload**
- **Connection information**
- **Tool descriptions**

## 🔗 VS Code Integration

Once connected, GitHub Copilot can use the MCP tools:

```python
# Example: Analyze firmware
result = await mcp.tools.call("identify_file_format", {
    "file_path": "/path/to/firmware.bin"
})

# Example: Crack password
result = await mcp.tools.call("crack_md5_password", {
    "password_hash": "$1$salt$hash"
})
```

## 🐛 Troubleshooting

### Connection Issues

1. **Check if server is running**:
   ```bash
   ps aux | grep firmware_analyzer_mcp_sse
   ```

2. **Check port availability**:
   ```bash
   ss -tlnp | grep 8083
   ```

3. **Test SSE connection**:
   ```bash
   curl -N http://localhost:8083/sse
   ```

### VS Code Issues

1. **Check MCP extension** is installed
2. **Verify configuration** in VS Code settings
3. **Check logs** in VS Code output panel
4. **Restart VS Code** after configuration changes

### Permission Issues

1. **Make scripts executable**:
   ```bash
   chmod +x firmware_analyzer_mcp_sse.py sse_to_stdio_bridge.py
   ```

2. **Check file permissions**:
   ```bash
   ls -la *.py
   ```

## 📊 Advantages of SSE Implementation

- **Real-time communication** with automatic reconnection
- **Better error handling** and connection management
- **Reduced latency** compared to polling
- **Native browser support** for web interface
- **Scalable architecture** for multiple clients
- **Direct VS Code integration** via stdio bridge

## 🔄 Comparison with Other Implementations

| Feature | Stdio | HTTP | SSE |
|---------|-------|------|-----|
| VS Code Integration | ✅ Direct | ❌ Bridge needed | ✅ Via bridge |
| Real-time Updates | ❌ | ❌ | ✅ |
| Web Interface | ❌ | ✅ | ✅ |
| Multiple Clients | ❌ | ✅ | ✅ |
| Connection Management | ❌ | ❌ | ✅ |
| Error Recovery | ❌ | ❌ | ✅ |

## 📝 License

This implementation is part of the firmware analysis project and follows the same license terms. 