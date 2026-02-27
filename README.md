# 🔬 NullSec KernSpy

<div align="center">

![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go)
![Security](https://img.shields.io/badge/Security-Secure-red?style=for-the-badge&logo=shield)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux)
![License](https://img.shields.io/badge/License-Proprietary-purple?style=for-the-badge)

**Secure Linux Kernel Module Analyzer**

*Memory-safe kernel module inspection with defense-in-depth architecture*

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Security](#security)

</div>

---

## 🎯 Overview

NullSec KernSpy is a Secure Linux kernel module analyzer written in Go. It provides deep inspection of loaded kernel modules with comprehensive security features to prevent exploitation during analysis.

## ✨ Features

- **🔍 Module Analysis** - Comprehensive kernel module inspection
- **📊 Hash Verification** - SHA256 integrity checks for module files
- **🛡️ Privilege Verification** - Validates proper permissions before operations
- **⚡ Concurrent Scanning** - Go's goroutines for parallel analysis
- **🔒 Memory-Safe** - Go runtime prevents memory corruption
- **📝 Detailed Reports** - Module metadata, dependencies, and signatures

## 🛡️ Security Features

```
┌─────────────────────────────────────────────┐
│        NullSec KernSpy v2.0.0              │
├─────────────────────────────────────────────┤
│  ✓ Input Validation & Sanitization         │
│  ✓ Privilege Verification                  │
│  ✓ Rate Limiting on Operations             │
│  ✓ Memory-Safe by Design (Go Runtime)      │
│  ✓ Defense-in-Depth Architecture           │
│  ✓ Path Traversal Protection               │
│  ✓ Null Byte Injection Prevention          │
└─────────────────────────────────────────────┘
```

## 📦 Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/bad-antics/nullsec-kernspy.git
cd nullsec-kernspy

# Build with optimizations
go build -ldflags="-s -w" -o nullsec-kernspy kernspy.go

# Install system-wide (optional)
sudo mv nullsec-kernspy /usr/local/bin/
```

### Requirements

- Go 1.21 or later
- Linux kernel with `/proc/modules` access
- Root privileges for full functionality

## 🚀 Usage

```bash
# List loaded kernel modules
sudo ./nullsec-kernspy --list

# Analyze specific module
sudo ./nullsec-kernspy --analyze <module_name>

# Generate integrity report
sudo ./nullsec-kernspy --report --output modules.json

# Check module signatures
sudo ./nullsec-kernspy --verify-signatures

# Compare against baseline
sudo ./nullsec-kernspy --baseline baseline.json --diff
```

### Command Line Options

| Flag | Description |
|------|-------------|
| `--list` | List all loaded kernel modules |
| `--analyze <name>` | Deep analyze specific module |
| `--report` | Generate comprehensive report |
| `--verify-signatures` | Check module cryptographic signatures |
| `--baseline <file>` | Compare against known-good baseline |
| `--output <file>` | Output file for reports |
| `--verbose` | Enable verbose output |
| `--version` | Show version information |

## 📊 Output Example

```
██╗  ██╗███████╗██████╗ ███╗   ██╗███████╗██████╗ ██╗   ██╗
██║ ██╔╝██╔════╝██╔══██╗████╗  ██║██╔════╝██╔══██╗╚██╗ ██╔╝
█████╔╝ █████╗  ██████╔╝██╔██╗ ██║███████╗██████╔╝ ╚████╔╝ 
██╔═██╗ ██╔══╝  ██╔══██╗██║╚██╗██║╚════██║██╔═══╝   ╚██╔╝  
██║  ██╗███████╗██║  ██║██║ ╚████║███████║██║        ██║   
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝        ╚═╝   
                bad-antics • Kernel Module Analyzer

[*] Scanning /proc/modules...
[+] Found 142 loaded modules
[*] Analyzing module: nvidia
    ├── Size: 51,396,608 bytes
    ├── Dependencies: drm, i2c_core
    ├── State: Live
    ├── Hash: a7b8c9d0e1f2...
    └── Signed: Yes (NVIDIA Corporation)
```

## 🔐 Security Considerations

- **Always run with minimal required privileges**
- **Validate output before automated processing**
- **Use baselines from trusted sources**
- **Report suspicious modules to security team**

## 📜 License

NullSec Proprietary License - See LICENSE file for details.

## 👤 Author

**bad-antics**
- GitHub: [@bad-antics](https://github.com/bad-antics)
- Website: [bad-antics.github.io](https://bad-antics.github.io)
- Twitter: [x.com/AnonAntics](https://x.com/AnonAntics)

---

<div align="center">

**Part of the NullSec Security Framework**

*"Memory-safe kernel analysis for the paranoid"*

</div>
