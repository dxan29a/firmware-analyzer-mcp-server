# Network-Based MCP Server for Firmware Analysis

A network-enabled Model Context Protocol (MCP) server for analyzing firmware files and extracting hardcoded passwords. This server accepts TCP connections and can handle multiple clients simultaneously.

## 🌐 Network Features

- **TCP/IP Communication** - Accepts connections over network
- **Multi-Client Support** - Handles multiple simultaneous connections
- **SSL/TLS Support** - Optional encrypted communication
- **Configurable Host/Port** - Flexible network configuration
- **Logging** - Comprehensive connection and operation logging

## 🚀 Quick Start

### 1. Start the Network Server

```bash
# Basic server (no SSL)
python3 firmware_analyzer_mcp_network.py --host 0.0.0.0 --port 8080

# With SSL (requires certificate files)
python3 firmware_analyzer_mcp_network.py --host 0.0.0.0 --port 8443 --ssl --cert server.crt --key server.key
```

### 2. Connect with Network Client

```bash
# Connect to local server
python3 network_mcp_client.py --firmware /path/to/firmware.bin

# Connect to remote server
python3 network_mcp_client.py --host 192.168.1.100 --port 8080 --firmware /path/to/firmware.bin

# Connect with SSL
python3 network_mcp_client.py --host 192.168.1.100 --port 8443 --ssl --firmware /path/to/firmware.bin
```

## 📋 Server Options

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--host` | Host to bind to | `0.0.0.0` |
| `--port` | Port to bind to | `8080` |
| `--ssl` | Enable SSL/TLS | `False` |
| `--cert` | SSL certificate file | Required if `--ssl` |
| `--key` | SSL private key file | Required if `--ssl` |

### Examples

```bash
# Bind to specific interface
python3 firmware_analyzer_mcp_network.py --host 192.168.1.100 --port 8080

# Use custom port
python3 firmware_analyzer_mcp_network.py --port 9000

# Enable SSL with certificates
python3 firmware_analyzer_mcp_network.py --ssl --cert server.crt --key server.key --port 8443
```

## 🔧 Client Options

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--host` | MCP server host | `localhost` |
| `--port` | MCP server port | `8080` |
| `--ssl` | Use SSL/TLS connection | `False` |
| `--firmware` | Path to firmware file | Required |

### Examples

```bash
# Analyze local firmware
python3 network_mcp_client.py --firmware firmware.bin

# Connect to remote server
python3 network_mcp_client.py --host 10.0.0.5 --port 8080 --firmware firmware.bin

# Use SSL connection
python3 network_mcp_client.py --host 10.0.0.5 --port 8443 --ssl --firmware firmware.bin
```

## 🔒 SSL/TLS Configuration

### Generate Self-Signed Certificate

```bash
# Generate private key
openssl genrsa -out server.key 2048

# Generate certificate
openssl req -new -x509 -key server.key -out server.crt -days 365
```

### Start Server with SSL

```bash
python3 firmware_analyzer_mcp_network.py --ssl --cert server.crt --key server.key --port 8443
```

## 🌍 Network Architecture

```
┌─────────────────┐    TCP/IP    ┌──────────────────┐
│   MCP Client    │ ──────────── │  MCP Server      │
│                 │              │                  │
│ - Network Client│              │ - Multi-client   │
│ - SSL Support   │              │ - Async handling │
│ - JSON-RPC      │              │ - Tool execution │
└─────────────────┘              └──────────────────┘
```

## 📊 Available Tools

The network server provides the same 6 tools as the stdio version:

1. **update_firmware** - Upload and validate firmware files
2. **identify_file_format** - Auto-detect file formats
3. **extract_with_binwalk** - Extract embedded files
4. **extract_squashfs** - Extract SquashFS filesystems
5. **find_password_files** - Locate password files
6. **crack_md5_password** - Crack password hashes

## 🔍 Usage Examples

### Example 1: Basic Network Analysis

```bash
# Terminal 1: Start server
python3 firmware_analyzer_mcp_network.py --port 8080

# Terminal 2: Run analysis
python3 network_mcp_client.py --firmware /home/alan/Downloads/A8000RU_V7.1cu.643_B20200521.zip
```

### Example 2: Remote Analysis

```bash
# On server machine (192.168.1.100)
python3 firmware_analyzer_mcp_network.py --host 0.0.0.0 --port 8080

# On client machine
python3 network_mcp_client.py --host 192.168.1.100 --port 8080 --firmware firmware.bin
```

### Example 3: Secure Analysis

```bash
# On server machine
python3 firmware_analyzer_mcp_network.py --ssl --cert server.crt --key server.key --port 8443

# On client machine
python3 network_mcp_client.py --host 192.168.1.100 --port 8443 --ssl --firmware firmware.bin
```

## 📝 Logging

The server provides comprehensive logging:

```
2024-07-31 23:45:12,345 - __main__ - INFO - MCP Server started on 0.0.0.0:8080
2024-07-31 23:45:15,678 - __main__ - INFO - New client connected from ('192.168.1.100', 54321)
2024-07-31 23:45:20,123 - __main__ - INFO - Client ('192.168.1.100', 54321) disconnected
```

## 🔧 Configuration Files

### MCP Network Config

```json
{
  "mcpServers": {
    "firmware-analyzer-network": {
      "command": "python3",
      "args": ["firmware_analyzer_mcp_network.py", "--host", "0.0.0.0", "--port", "8080"],
      "env": {
        "PYTHONPATH": "."
      }
    }
  }
}
```

## 🛡️ Security Considerations

### Network Security
- Use SSL/TLS for encrypted communication
- Bind to specific interfaces when possible
- Use firewall rules to restrict access
- Monitor connection logs

### Authentication
- Consider implementing authentication mechanisms
- Use VPN for remote access
- Implement rate limiting for connections

### File Security
- Ensure firmware files are from trusted sources
- Scan files for malware before analysis
- Use isolated environments for analysis

## 🚨 Troubleshooting

### Common Issues

1. **Connection Refused**
   ```bash
   # Check if server is running
   netstat -tlnp | grep 8080
   
   # Check firewall settings
   sudo ufw status
   ```

2. **SSL Certificate Errors**
   ```bash
   # Verify certificate
   openssl x509 -in server.crt -text -noout
   
   # Check certificate dates
   openssl x509 -in server.crt -noout -dates
   ```

3. **Port Already in Use**
   ```bash
   # Find process using port
   lsof -i :8080
   
   # Kill process
   sudo kill -9 <PID>
   ```

### Debug Mode

```bash
# Enable debug logging
export PYTHONPATH=.
python3 -u firmware_analyzer_mcp_network.py --port 8080 2>&1 | tee server.log
```

## 📈 Performance

### Multi-Client Handling
- Asynchronous connection handling
- Independent client sessions
- No blocking between clients

### Resource Usage
- Memory usage scales with active connections
- CPU usage depends on analysis operations
- Disk usage for temporary files

## 🔄 Migration from Stdio

### From Stdio to Network

1. **Replace server startup:**
   ```bash
   # Old (stdio)
   python3 firmware_analyzer_mcp.py
   
   # New (network)
   python3 firmware_analyzer_mcp_network.py --port 8080
   ```

2. **Update client calls:**
   ```bash
   # Old (stdio)
   python3 direct_firmware_analyzer.py
   
   # New (network)
   python3 network_mcp_client.py --firmware firmware.bin
   ```

## 📚 API Reference

### Server Methods

- `initialize()` - Initialize MCP protocol
- `tools/list` - List available tools
- `tools/call` - Execute tool with arguments

### Client Methods

- `connect()` - Connect to server
- `disconnect()` - Disconnect from server
- `send_request()` - Send JSON-RPC request
- `call_tool()` - Call specific tool

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Submit pull request

## 📄 License

This project is provided for educational and security research purposes. Use responsibly and in accordance with applicable laws and regulations.

---

**Network MCP Server** - Enabling remote firmware analysis with security and scalability. 