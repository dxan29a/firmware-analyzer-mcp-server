# 🔍 HTTP-based MCP Firmware Analyzer Server

A **Streaming HTTP-based MCP (Model Context Protocol) server** for firmware analysis and password extraction. This server provides a web interface and REST API for analyzing firmware files and finding hardcoded passwords.

## 🌟 **Features**

### **Web Interface**
- **Modern HTML5 UI** with responsive design
- **Real-time tool execution** via AJAX
- **Interactive forms** for all analysis tools
- **JSON response display** with syntax highlighting
- **Cross-origin support** (CORS enabled)

### **REST API**
- **RESTful endpoints** for all MCP tools
- **JSON request/response** format
- **HTTP status codes** for error handling
- **CORS support** for web applications
- **SSL/TLS support** for secure connections

### **Firmware Analysis Tools**
1. **Update Firmware** - Upload and validate `.bin` firmware files
2. **Identify File Format** - Detect ZIP, binary, SquashFS formats
3. **Extract with Binwalk** - Recursively extract files from binaries
4. **Extract SquashFS** - Open SquashFS filesystems
5. **Find Password Files** - Locate `/etc/passwd` and `/etc/shadow`
6. **Crack MD5 Password** - Attempt password cracking

## 🚀 **Quick Start**

### **1. Installation**

```bash
# Install system dependencies
sudo apt-get install binwalk squashfs-tools python3-magic libmagic1

# Install Python dependencies
sudo apt-get install python3-aiohttp python3-aiohttp-cors

# Or install all requirements
./install.sh
```

### **2. Start the HTTP Server**

```bash
# Basic server (port 8080)
python3 firmware_analyzer_mcp_http.py

# Custom port
python3 firmware_analyzer_mcp_http.py --port 8081

# SSL/TLS server
python3 firmware_analyzer_mcp_http.py --ssl --cert cert.pem --key key.pem
```

### **3. Access the Web Interface**

Open your browser and navigate to:
- **HTTP**: `http://localhost:8080`
- **HTTPS**: `https://localhost:8080` (if using SSL)

### **4. Use the REST API**

```bash
# Get available tools
curl http://localhost:8080/api/tools/list

# Update firmware
curl -X POST -H "Content-Type: application/json" \
  -d '{"firmware_path":"/path/to/firmware.bin"}' \
  http://localhost:8080/api/update_firmware

# Identify file format
curl -X POST -H "Content-Type: application/json" \
  -d '{"file_path":"/path/to/file"}' \
  http://localhost:8080/api/identify_file_format
```

## 📡 **HTTP API Reference**

### **Base URL**
```
http://localhost:8080
```

### **Endpoints**

#### **GET /** - Web Interface
Returns the HTML web interface for interactive use.

#### **GET /api/tools/list** - List Available Tools
Returns a list of all available MCP tools with their schemas.

**Response:**
```json
{
  "tools": [
    {
      "name": "update_firmware",
      "description": "Upload and update firmware (.bin file)",
      "inputSchema": {
        "type": "object",
        "properties": {
          "firmware_path": {
            "type": "string",
            "description": "Path to the firmware file (.bin)"
          }
        },
        "required": ["firmware_path"]
      }
    }
  ]
}
```

#### **POST /api/update_firmware** - Update Firmware
Upload and validate a firmware file.

**Request:**
```json
{
  "firmware_path": "/path/to/firmware.bin"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Firmware uploaded successfully: /path/to/firmware.bin",
  "file_size": 48999696
}
```

#### **POST /api/identify_file_format** - Identify File Format
Detect the format of a file and handle accordingly.

**Request:**
```json
{
  "file_path": "/path/to/file"
}
```

**Response:**
```json
{
  "file": "/path/to/file",
  "mime_type": "application/zip",
  "magic_info": "Zip archive data, at least v2.0 to extract",
  "detected_format": "ZIP",
  "extracted_path": "/tmp/firmware_zip_abc123",
  "next_step": "Use find_password_files tool with the extracted directory path"
}
```

#### **POST /api/extract_with_binwalk** - Extract with Binwalk
Use binwalk to recursively extract files from binary.

**Request:**
```json
{
  "binary_path": "/path/to/binary"
}
```

#### **POST /api/extract_squashfs** - Extract SquashFS
Use unsquash tool to open a SquashFS filesystem.

**Request:**
```json
{
  "squashfs_path": "/path/to/squashfs"
}
```

#### **POST /api/find_password_files** - Find Password Files
Find `/etc/passwd` and `/etc/shadow` files in extracted filesystem.

**Request:**
```json
{
  "extracted_path": "/path/to/extracted"
}
```

#### **POST /api/crack_md5_password** - Crack MD5 Password
Try to crack MD5-crypt passwords using various methods.

**Request:**
```json
{
  "password_hash": "$1$salt$hash",
  "wordlist_path": "/path/to/wordlist.txt"
}
```

## 🔧 **Server Options**

```bash
python3 firmware_analyzer_mcp_http.py [OPTIONS]

Options:
  --host HOST          Host to bind to (default: 0.0.0.0)
  --port PORT          Port to bind to (default: 8080)
  --ssl                Enable SSL/TLS
  --cert CERT          SSL certificate file
  --key KEY            SSL private key file
  -h, --help           Show help message
```

## 🌐 **Client Usage**

### **Python HTTP Client**

```python
import asyncio
from http_mcp_client import HTTPMCPClient

async def analyze_firmware():
    async with HTTPMCPClient("http://localhost:8080") as client:
        # Update firmware
        result = await client.call_tool("update_firmware", {
            "firmware_path": "/path/to/firmware.bin"
        })
        print(result)
        
        # Identify format
        result = await client.call_tool("identify_file_format", {
            "file_path": "/path/to/firmware.bin"
        })
        print(result)

# Run the analysis
asyncio.run(analyze_firmware())
```

### **Command Line Client**

```bash
# Test tools list
python3 http_mcp_client.py --test-tools --server http://localhost:8080

# Analyze firmware
python3 http_mcp_client.py --firmware /path/to/firmware.bin --server http://localhost:8080
```

### **JavaScript/Web Client**

```javascript
// Call a tool
async function callTool(toolName, arguments) {
    const response = await fetch(`http://localhost:8080/api/${toolName}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(arguments)
    });
    
    if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    return await response.json();
}

// Example usage
const result = await callTool('update_firmware', {
    firmware_path: '/path/to/firmware.bin'
});
console.log(result);
```

## 🔒 **Security Features**

### **CORS Support**
- **Cross-origin requests** enabled for web applications
- **Configurable CORS policies** for production use
- **Preflight request handling** for complex requests

### **SSL/TLS Support**
```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Start SSL server
python3 firmware_analyzer_mcp_http.py --ssl --cert cert.pem --key key.pem
```

### **Input Validation**
- **JSON schema validation** for all tool inputs
- **File path validation** to prevent directory traversal
- **Error handling** with appropriate HTTP status codes

## 📊 **Performance**

### **Concurrent Requests**
- **Asynchronous I/O** using aiohttp
- **Non-blocking operations** for multiple clients
- **Connection pooling** for efficient resource usage

### **Memory Management**
- **Temporary file cleanup** after extraction
- **Streaming responses** for large files
- **Resource limits** to prevent DoS attacks

## 🔍 **Troubleshooting**

### **Common Issues**

#### **Port Already in Use**
```bash
# Check what's using the port
sudo netstat -tlnp | grep :8080

# Kill the process or use a different port
python3 firmware_analyzer_mcp_http.py --port 8081
```

#### **Permission Denied**
```bash
# Make sure the script is executable
chmod +x firmware_analyzer_mcp_http.py

# Run with appropriate permissions
sudo python3 firmware_analyzer_mcp_http.py
```

#### **Missing Dependencies**
```bash
# Install missing packages
sudo apt-get install python3-aiohttp python3-aiohttp-cors

# Check installation
python3 -c "import aiohttp, aiohttp_cors; print('Dependencies OK')"
```

### **Logging**
The server provides detailed logging for debugging:
```bash
# View server logs
python3 firmware_analyzer_mcp_http.py 2>&1 | tee server.log
```

## 🆚 **Comparison: HTTP vs TCP vs stdio**

| Feature | HTTP Server | TCP Server | stdio Server |
|---------|-------------|------------|--------------|
| **Protocol** | HTTP/HTTPS | Raw TCP | stdio |
| **Web Interface** | ✅ Built-in | ❌ No | ❌ No |
| **REST API** | ✅ Yes | ❌ No | ❌ No |
| **Browser Support** | ✅ Yes | ❌ No | ❌ No |
| **CORS Support** | ✅ Yes | ❌ No | ❌ No |
| **SSL/TLS** | ✅ Native | ✅ Manual | ❌ No |
| **MCP Compliance** | ⚠️ Custom | ✅ Yes | ✅ Yes |
| **Performance** | ⚠️ HTTP overhead | ✅ Fast | ✅ Fastest |
| **Ease of Use** | ✅ Very Easy | ⚠️ Moderate | ⚠️ Moderate |

## 📝 **Examples**

### **Complete Firmware Analysis Workflow**

```bash
# 1. Start the server
python3 firmware_analyzer_mcp_http.py --port 8080 &

# 2. Open web interface
xdg-open http://localhost:8080

# 3. Or use command line client
python3 http_mcp_client.py --firmware /path/to/firmware.bin --server http://localhost:8080

# 4. Or use curl
curl -X POST -H "Content-Type: application/json" \
  -d '{"firmware_path":"/path/to/firmware.bin"}' \
  http://localhost:8080/api/update_firmware
```

### **Integration with Web Applications**

```html
<!DOCTYPE html>
<html>
<head>
    <title>Firmware Analyzer</title>
</head>
<body>
    <h1>Firmware Analyzer</h1>
    <input type="file" id="firmwareFile" accept=".bin,.zip">
    <button onclick="analyzeFirmware()">Analyze</button>
    <div id="result"></div>

    <script>
        async function analyzeFirmware() {
            const file = document.getElementById('firmwareFile').files[0];
            if (!file) return;

            const result = await fetch('http://localhost:8080/api/update_firmware', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({firmware_path: file.name})
            });

            const data = await result.json();
            document.getElementById('result').textContent = JSON.stringify(data, null, 2);
        }
    </script>
</body>
</html>
```

## 🤝 **Contributing**

1. **Fork the repository**
2. **Create a feature branch**
3. **Make your changes**
4. **Add tests if applicable**
5. **Submit a pull request**

## 📄 **License**

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔗 **Related Projects**

- **TCP MCP Server**: `firmware_analyzer_mcp_network.py`
- **stdio MCP Server**: `firmware_analyzer_mcp.py`
- **Direct Analysis**: `direct_firmware_analyzer.py`

---

**🎉 The HTTP-based MCP server provides the easiest way to integrate firmware analysis into web applications and provides a user-friendly interface for security researchers and developers!** 