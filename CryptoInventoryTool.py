import os
import sqlite3
import re
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

DB_FILE = "crypto_inventory.db" #database name
Total_files = 0 #Number of files in folder

BEST_PRACTICES = {
    "MD5": "High",
    "SHA1": "High",
    "DES": "High",
    "3DES": "Medium",
    "AES-128": "Low",
    "HardcodedKey": "Medium",
    "RSA/ECB/NoPadding": "High",
}

RISK_LEVELS = {
    "High": "Critical findings that can lead to severe compromise. Must be addressed immediately.",
    "Medium": "Moderate findings that increase risk. Should be addressed soon.",
    "Low": "Non-critical issues. Recommended to follow best practices.",
}

# Initialize the database
def initialize_database():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT,
            issue TEXT,
            severity TEXT
        )
    """)
    conn.commit()
    conn.close()

# Scan file for weak cryptographic primitives
def scan_file(file_path):
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            # Detect 3DES
            if "3DES" in content:
                findings.append((file_path, "3DES", "High"))
            # Detect DES
            elif "DES" in content:
                findings.append((file_path, "DES", "High"))
            # Detect Weak Hardcoded Keys
            elif "AES" in content and re.search(r"Key = \".{0,1000000000}\"",content): #max acceptable number for regex
                findings.append((file_path, "Weak Hardcoded Key", "Medium"))
            # Detect RSA with short keys
            elif "RSA" in content and re.search(r"nextprime\(.{0,1000000000}\)", content): #max acceptable number for regex
                findings.append((file_path, "RSA with short keys", "High"))
            # Detect weak random key generation
            elif re.search(r"Random\(.+\)|SystemRandom\(\)", content):
                findings.append((file_path, "Weak random key generation", "Medium"))
            # Detect RSA without proper padding
            elif "RSA" in content and not re.search(r"(OAEP|PKCS1v15)", content):
                findings.append((file_path, "RSA without proper padding", "High"))
            # Detect MD5 usage
            elif re.search(r"MD5", content):
                findings.append((file_path, "MD5 usage", "High"))
            # Detect SHA1 usage
            elif re.search(r"SHA1", content):
                findings.append((file_path, "SHA1 usage", "High"))
            # Detect AES in ECB mode
            elif "AES" in content and "ecb" in content:
                findings.append((file_path, "AES in ECB mode", "High"))
    except Exception as e:
        print(f"Error scanning file {file_path}: {e}")
    return findings

# Scan folder for files
def scan_folder(folder_path):
    all_findings = []
    global Total_files
    Total_files = 0
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith((".py", ".java", ".c")):
                Total_files+=1
                findings = scan_file(file_path)
                all_findings.extend(findings)
    return all_findings

# Save findings to database
def save_to_database(findings):
    conn = sqlite3.connect("crypto_inventory.db")
    cursor = conn.cursor()
    cursor.executemany("INSERT INTO findings (file_path, issue, severity) VALUES (?, ?, ?)", findings)
    conn.commit()
    conn.close()

class CryptoInventoryTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptographic Asset Inventory Tool")

        # GUI Elements
        self.folder_path = tk.StringVar()

        # Input for folder selection
        tk.Label(root, text="Folder to Scan:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        tk.Entry(root, textvariable=self.folder_path, width=50).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(root, text="Browse", command=self.browse_folder).grid(row=0, column=2, padx=5, pady=5)
        tk.Button(root, text="Scan", command=self.scan_folder).grid(row=0, column=3, padx=5, pady=5)

        # Findings Table
        self.tree = ttk.Treeview(root, columns=("File", "Issue", "Severity"), show="headings", height=15)
        self.tree.grid(row=1, column=0, columnspan=4, padx=5, pady=5)
        self.tree.heading("File", text="File")
        self.tree.heading("Issue", text="Issue")
        self.tree.heading("Severity", text="Severity")
        self.tree.column("File", width=300)
        self.tree.column("Issue", width=150)
        self.tree.column("Severity", width=100)
        self.tree.bind("<Button-1>", self.sort_column)

        # Buttons for additional functionalities
        tk.Button(root, text="Explain Risk Levels", command=self.explain_risk_levels).grid(row=2, column=0, pady=5)
        tk.Button(root, text="Print Statistics", command=self.print_statistics).grid(row=2, column=1, pady=5)
        tk.Button(root, text="Clear Findings", command=self.clear_findings).grid(row=2, column=2, pady=5)

    def browse_folder(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.folder_path.set(folder_selected)
            self.folder_path = folder_selected

    def scan_folder(self):
        if hasattr(self,"folder_path") and self.folder_path:
            findings = scan_folder(self.folder_path)

        if findings:
            save_to_database(findings)
            for file_path, issue, severity in findings:
                self.tree.insert("","end",values=(file_path,issue,severity))
            total_findings = len(findings)
            messagebox.showinfo("Scan complete",f"Scan completed successfully.\nNumer of files scanned: {Total_files}\nTotal findings: {total_findings}")
        else:
            messagebox.showinfo("Scan complete",f"Scan completed successfully.\nNumer of files scanned: {Total_files}\nNo vulnerabilities found.")

    def explain_risk_levels(self):
        explanation = "\n".join([f"{level}: {desc}" for level, desc in RISK_LEVELS.items()])
        messagebox.showinfo("Risk Levels", explanation)

    def print_statistics(self):
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        # Fetch statistics
        cursor.execute("SELECT COUNT(DISTINCT file_path) FROM findings")
        total_vulnerable_files = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM findings")
        total_findings = cursor.fetchone()[0]

        conn.close()

        stats_text = (
            f"Total vulnerable files: {total_vulnerable_files}\n"
            f"Total findings: {total_findings}"
        )
        messagebox.showinfo("Scan Statistics", stats_text)

    def clear_findings(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM findings")
        conn.commit()
        conn.close()

    def sort_column(self, event):
        data = [(self.tree.set(child, "Severity"), child) for child in self.tree.get_children()]
        data.sort(key=lambda x: x[0])
        for index, (_, child) in enumerate(data):
            self.tree.move(child, "", index)


if __name__ == "__main__":
    initialize_database()
    root = tk.Tk()
    app = CryptoInventoryTool(root)
    root.mainloop()