# File Analyzer MCP Server

[![MCP](https://img.shields.io/badge/MCP-Compatible-blue)](https://modelcontextprotocol.io)
[![Python-3.10+](https://img.shields.io/badge/Python-3.10%2B-green)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Part of Agentic System](https://img.shields.io/badge/Part_of-Agentic_System-brightgreen)](https://github.com/marc-shade/agentic-system-oss)

> **Deep file analysis and malware detection capabilities.**

Part of the [Agentic System](https://github.com/marc-shade/agentic-system-oss) - a 24/7 autonomous AI framework with persistent memory.

Cybersecurity file analysis tool using magic numbers to identify true file types.

## Features

- **Magic Number Detection**: Identify file types by header bytes, not extensions
- **Extension Mismatch Detection**: Find files with suspicious extension/content mismatches
- **Hash Calculation**: MD5, SHA1, SHA256 for file integrity and threat lookup
- **Threat Integration**: Check file hashes against threat intelligence feeds
- **Batch Scanning**: Scan directories for suspicious files
- **Entropy Analysis**: Detect potentially encrypted/packed files

## Tools

| Tool | Description |
|------|-------------|
| `identify_file` | Get true file type from magic bytes |
| `calculate_hashes` | Get MD5, SHA1, SHA256 hashes |
| `check_extension_mismatch` | Detect disguised files |
| `scan_directory` | Batch scan for suspicious files |
| `analyze_entropy` | Detect encrypted/packed content |
| `check_file_reputation` | Check hash against threat feeds |

## Magic Numbers Reference

Common file signatures detected:
- **PE Executable**: `4D 5A` (MZ)
- **ELF Binary**: `7F 45 4C 46`
- **PDF**: `25 50 44 46` (%PDF)
- **ZIP/Office**: `50 4B 03 04` (PK)
- **JPEG**: `FF D8 FF`
- **PNG**: `89 50 4E 47`
- **GIF**: `47 49 46 38`
---

## Part of the MCP Ecosystem

This server integrates with other MCP servers for comprehensive AGI capabilities:

| Server | Purpose |
|--------|---------|
| [enhanced-memory-mcp](https://github.com/marc-shade/enhanced-memory-mcp) | 4-tier persistent memory with semantic search |
| [agent-runtime-mcp](https://github.com/marc-shade/agent-runtime-mcp) | Persistent task queues and goal decomposition |
| [agi-mcp](https://github.com/marc-shade/agi-mcp) | Full AGI orchestration with 21 tools |
| [cluster-execution-mcp](https://github.com/marc-shade/cluster-execution-mcp) | Distributed task routing across nodes |
| [node-chat-mcp](https://github.com/marc-shade/node-chat-mcp) | Inter-node AI communication |
| [ember-mcp](https://github.com/marc-shade/ember-mcp) | Production-only policy enforcement |

See [agentic-system-oss](https://github.com/marc-shade/agentic-system-oss) for the complete framework.
