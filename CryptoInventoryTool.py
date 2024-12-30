import os
import sqlite3
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Database setup
DB_FILE = "crypto_inventory.db"
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
    "High": "Critical vulnerabilities that can lead to severe compromise. Must be addressed immediately.",
    "Medium": "Moderate vulnerabilities that increase risk. Should be addressed soon.",
    "Low": "Non-critical issues. Recommended to follow best practices.",
}

# Initialize the database
def initialize_database():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY,
            file_path TEXT,
            issue TEXT,
            severity TEXT
        )
    """)
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

    def scan_folder(self):
        folder = self.folder_path.get()
        if not folder:
            messagebox.showerror("Error", "Please select a folder to scan.")
            return

        self.clear_findings()

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        # Scan files and detect vulnerabilities
        files_scanned = 0
        vulnerabilities = {}
        for root, _, files in os.walk(folder):
            for file in files:
                file_path = os.path.join(root, file)
                file_extension = file.split(".")[-1].lower()
                files_scanned += 1

                # Analyze file
                issues = self.analyze_file(file_path)
                if issues:
                    if file_extension not in vulnerabilities:
                        vulnerabilities[file_extension] = 0
                    vulnerabilities[file_extension] += 1

                    # Store findings in database and table
                    for issue, severity in issues:
                        cursor.execute(
                            "INSERT INTO findings (file_path, issue, severity) VALUES (?, ?, ?)",
                            (file_path, issue, severity),
                        )
                        self.tree.insert("", "end", values=(file_path, issue, severity))

        conn.commit()
        conn.close()

        # Display scan statistics
        total_vulnerabilities = sum(vulnerabilities.values())
        messagebox.showinfo(
            "Scan Complete",
            f"Total files scanned: {files_scanned}\n"
            f"Vulnerable files found: {total_vulnerabilities}\n"
            + "\n".join([f"{ext}: {count}" for ext, count in vulnerabilities.items()]),
        )

    def analyze_file(self, file_path):
        issues = []
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                content = file.read()
                for issue, severity in BEST_PRACTICES.items():
                    if issue in content:
                        issues.append((issue, severity))
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
        return issues

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
