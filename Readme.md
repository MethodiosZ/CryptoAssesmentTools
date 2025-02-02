# Crypto Inventory & Simulation Tools - Installation & Configuration Guide

## Overview
The **Crypto Inventory Tool** and **Crypto Simulation Tool** help identify and analyze cryptographic vulnerabilities in source code files. The Inventory Tool scans for weak cryptographic implementations, while the Simulation Tool suggests replacements for outdated algorithms.

## System Requirements
- Python 3.x
- SQLite3
- Tkinter (GUI support)
 
**Install Dependencies** (if needed)
   ```sh
   pip install tkinter
   ```
   Tkinter is usually included in Python distributions.

## Configuration
Both tools use an SQLite database (`crypto_inventory.db`) to store cryptographic findings.

### Initializing the Database
Before running the tools, initialize the database:
```sh
python -c "import sqlite3; sqlite3.connect('crypto_inventory.db').close()"
```
This ensures the database file is available.

## Running the Tools

### Crypto Inventory Tool
This tool scans a folder for cryptographic vulnerabilities.

#### Steps:
1. Run the tool:
   ```sh
   python CryptoInventoryTool.py
   ```
2. Select a folder to scan.
3. Click **Scan** to identify vulnerabilities.
4. Use **Export to CSV** to save results.
5. Click **Help** to open the documentation.

### Crypto Simulation Tool
This tool suggests replacements for weak cryptographic primitives found in `crypto_inventory.db`.

#### Steps:
1. Run the tool:
   ```sh
   python CryptoSimulationTool.py
   ```
2. A table will display detected vulnerabilities and suggested fixes.
3. Double-click a row to see recommendations.

## Notes
- Ensure Python has permissions to read and write `crypto_inventory.db`.
- Use strong cryptographic algorithms as recommended in the Simulation Tool.
