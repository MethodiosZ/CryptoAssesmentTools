import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox

# Mapping weak cryptographic primitives to recommended replacements
REPLACEMENT_MAP = {
    "MD5": "SHA-256",
    "SHA1": "SHA-256",
    "DES": "AES-256",
    "3DES": "AES-256",
    "AES-128": "AES-256",
    "AES in ECB mode": "AES-256",
    "Weak Hardcoded Key": "Strong Random Key Generator",
    "Weak random key generation": "Strong Random Key Generator",
    "RSA with short keys": "Kyber",
    "RSA without proper padding": "RSA/OAEP"
}

DB_FILE = "crypto_inventory.db"

def fetch_findings():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT file_path, issue, severity FROM findings")
    findings = cursor.fetchall()
    conn.close()
    return findings

def suggest_manual_fixes(issue, severity):
    return f"- {issue} ({severity} risk) should be replaced with a more secure alternative."

def show_suggestions(file_path, issues):
    suggestions = "\n".join(issues)
    messagebox.showinfo(f"Suggestions for {file_path}", suggestions)

def populate_tree():
    findings = fetch_findings()
    if not findings:
        print("No vulnerabilities found in the database.")
        return
    for file_path, issue, severity in findings:
        if file_path not in file_suggestions:
            file_suggestions[file_path] = []
        file_suggestions[file_path].append(suggest_manual_fixes(issue, severity))
        tree.insert("", "end", values=(file_path, issue, severity))

def on_select(event):
    selected_item = tree.selection()
    if selected_item:
        file_path = tree.item(selected_item, "values")[0]
        show_suggestions(file_path, file_suggestions.get(file_path, []))

# GUI setup
root = tk.Tk()
root.title("Cryptographic Vulnerability Viewer")

file_suggestions = {}

# Table setup
tree = ttk.Treeview(root, columns=("File", "Issue", "Severity"), show="headings", height=15)
tree.heading("File", text="File")
tree.heading("Issue", text="Issue")
tree.heading("Severity", text="Severity")
tree.column("File", width=300)
tree.column("Issue", width=200)
tree.column("Severity", width=100)
tree.bind("<Double-1>", on_select)
tree.pack(fill=tk.BOTH, expand=True)

populate_tree()

root.mainloop()