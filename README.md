# 🔍 Firmware Analyzer MCP Server Collection

A comprehensive collection of **Model Context Protocol (MCP) servers** for firmware analysis and password extraction, implemented across three different transport protocols.

## 📁 **Project Structure**

```
rock-firmware/
├── stdio/              # Standard stdio-based MCP server
├── network/            # TCP network-based MCP server  
├── streaming-http/     # HTTP/HTTPS streaming MCP server
├── requirements.txt    # Python dependencies
├── install.sh         # Installation script
├── firmware_analysis_report.html  # HTML analysis report
├── firmware_analysis_report.md    # Markdown analysis report
└── README.md          # This file
```

## 🚀 **Quick Start**

### **1. Installation**
```bash
# Install all dependencies
./install.sh

# Or install manually
sudo apt-get install binwalk squashfs-tools python3-magic libmagic1 python3-aiohttp python3-aiohttp-cors
pip install -r requirements.txt
```

### **2. Choose Your Transport**

#### **🌐 HTTP Server (Recommended for Web)**
```bash
cd streaming-http
python3 firmware_analyzer_mcp_http.py --port 8080
# Open browser: http://localhost:8080
```

#### **🌐 Network Server (Recommended for CLI)**
```bash
cd network
python3 firmware_analyzer_mcp_network.py --port 8080
python3 network_mcp_client.py --firmware /path/to/firmware.bin
```

#### **📡 stdio Server (Standard MCP)**
```bash
cd stdio
python3 firmware_analyzer_mcp.py
# Use with MCP clients
```

## 🔧 **Available Tools**

All three implementations provide the same 6 analysis tools:

1. **`update_firmware`** - Upload and validate `.bin` firmware files
2. **`identify_file_format`** - Detect ZIP, binary, SquashFS formats
3. **`extract_with_binwalk`** - Recursively extract files from binaries
4. **`extract_squashfs`** - Open SquashFS filesystems
5. **`find_password_files`** - Locate `/etc/passwd` and `/etc/shadow`
6. **`crack_md5_password`** - Attempt password cracking

## 🆚 **Transport Comparison**

| Feature | stdio | Network | HTTP |
|---------|-------|---------|------|
| **Protocol** | stdio | TCP | HTTP/HTTPS |
| **Web Interface** | ❌ | ❌ | ✅ Built-in |
| **REST API** | ❌ | ❌ | ✅ Yes |
| **Browser Support** | ❌ | ❌ | ✅ Yes |
| **Multi-Client** | ❌ | ✅ Yes | ✅ Yes |
| **SSL/TLS** | ❌ | ✅ Manual | ✅ Native |
| **MCP Compliance** | ✅ Full | ✅ Full | ⚠️ Custom |
| **Performance** | ✅ Fastest | ✅ Fast | ⚠️ HTTP overhead |
| **Ease of Use** | ⚠️ Moderate | ⚠️ Moderate | ✅ Very Easy |
| **Integration** | ⚠️ MCP only | ⚠️ TCP only | ✅ Universal |

## 📖 **Documentation**

- **[stdio/](stdio/)** - Standard MCP server with stdio transport
- **[network/](network/)** - TCP network server with multi-client support
- **[streaming-http/](streaming-http/)** - HTTP server with web interface and REST API

## 🎯 **Use Cases**

### **Choose stdio if:**
- You need full MCP protocol compliance
- You're integrating with existing MCP clients
- You want maximum performance
- You're building command-line tools

### **Choose Network if:**
- You need multi-client support
- You want remote access capabilities
- You need SSL/TLS encryption
- You're building distributed systems

### **Choose HTTP if:**
- You want a web interface
- You need REST API integration
- You're building web applications
- You want the easiest setup and usage
- You need browser-based access

## 🔍 **Analysis Reports**

The project includes analysis reports from previous firmware analysis:

- **`firmware_analysis_report.html`** - Interactive HTML report with findings
- **`firmware_analysis_report.md`** - Markdown summary of analysis results

## 🛠️ **Development**

### **Testing**
```bash
# Test stdio server
cd stdio && python3 direct_firmware_analyzer.py

# Test network server
cd network && python3 test_network_connection.py

# Test HTTP server
cd streaming-http && python3 http_mcp_client.py --test-tools
```

### **Adding New Tools**
All three implementations share the same core analysis functions. To add a new tool:

1. Add the function to the core analysis logic
2. Update all three server implementations
3. Update client examples
4. Update documentation

## 🔒 **Security**

- **Password hashes are masked** in output for security
- **Temporary files** are cleaned up automatically
- **Input validation** prevents directory traversal
- **SSL/TLS support** for secure communications
- **CORS policies** for web security

## 📄 **License**

This project is provided for educational and security research purposes. Use responsibly and in accordance with applicable laws and regulations.

## 🤝 **Contributing**

1. **Fork the repository**
2. **Create a feature branch**
3. **Make your changes** across all three implementations
4. **Add tests** if applicable
5. **Submit a pull request**

---

**🎉 Choose the transport that best fits your needs and start analyzing firmware today!** 