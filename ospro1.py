import os
import hashlib
import shutil
import psutil
import time
import tkinter as tk
from tkinter import filedialog, messagebox

def scan_file_system():
    path = filedialog.askdirectory(title="Select Directory to Scan")
    if not path:
        return
    report_file = "scan_report.txt"
    with open(report_file, "w") as report:
        for root, dirs, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                size = os.path.getsize(file_path)
                modified_time = time.ctime(os.path.getmtime(file_path))
                report.write(f"{file_path}, {size} bytes, Modified: {modified_time}\n")
    messagebox.showinfo("Scan Complete", f"Report saved to {report_file}")

def find_duplicate_files():
    path = filedialog.askdirectory(title="Select Directory to Search for Duplicates")
    if not path:
        return
    file_hashes = {}
    duplicates = []
    
    for root, _, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            hash_obj = hashlib.sha256()
            try:
                with open(file_path, "rb") as f:
                    hash_obj.update(f.read())
                file_hash = hash_obj.hexdigest()
                if file_hash in file_hashes:
                    duplicates.append((file_path, file_hashes[file_hash]))
                else:
                    file_hashes[file_hash] = file_path
            except Exception as e:
                messagebox.showerror("Error", f"Error reading {file_path}: {e}")
    
    if duplicates:
        msg = "Duplicate files found:\n" + "\n".join([f"{dup[0]} is a duplicate of {dup[1]}" for dup in duplicates])
        if messagebox.askyesno("Duplicates Found", msg + "\n\nDelete duplicates?"):
            for dup in duplicates:
                os.remove(dup[0])
        messagebox.showinfo("Operation Complete", "Duplicate files processed.")
    else:
        messagebox.showinfo("No Duplicates", "No duplicate files found.")

def recover_files():
    path = filedialog.askdirectory(title="Select Directory to Search for Deleted Files")
    if not path:
        return
    ext = extension_entry.get().strip()
    if not ext:
        messagebox.showwarning("Input Required", "Please enter a file extension (e.g., .txt, .jpg)")
        return
    recovered_dir = "recovered_files"
    os.makedirs(recovered_dir, exist_ok=True)
    recovered_count = 0
    
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(ext):
                source = os.path.join(root, file)
                destination = os.path.join(recovered_dir, f"recovered_{file}")
                shutil.copy2(source, destination)
                recovered_count += 1
    
    messagebox.showinfo("Recovery Complete", f"{recovered_count} files recovered.") if recovered_count else messagebox.showinfo("No Files Recovered", "No matching files found.")

def optimize_system():
    disk_usage = psutil.disk_usage('/')
    temp_dirs = ["/tmp", os.path.expanduser("~/tmp")]
    deleted_count = 0
    
    for temp_dir in temp_dirs:
        if os.path.exists(temp_dir):
            for file in os.listdir(temp_dir):
                file_path = os.path.join(temp_dir, file)
                try:
                    os.remove(file_path)
                    deleted_count += 1
                except Exception:
                    pass
    
    messagebox.showinfo("Optimization Complete", f"Disk Usage: {disk_usage.percent}% used. Cleaned {deleted_count} temporary files.")

# GUI Setup
root = tk.Tk()
root.title("File System Recovery & Optimization Tool")
root.geometry("500x400")

tk.Label(root, text="Select an operation:", font=("Arial", 14)).pack(pady=10)

tk.Button(root, text="Scan File System", command=scan_file_system, width=30).pack(pady=5)
tk.Button(root, text="Find and Delete Duplicates", command=find_duplicate_files, width=30).pack(pady=5)

tk.Label(root, text="File Extension for Recovery:").pack(pady=5)
extension_entry = tk.Entry(root)
extension_entry.pack(pady=5)
tk.Button(root, text="Recover Deleted Files", command=recover_files, width=30).pack(pady=5)

tk.Button(root, text="Optimize System", command=optimize_system, width=30).pack(pady=5)
tk.Button(root, text="Exit", command=root.quit, width=30, fg="red").pack(pady=20)

root.mainloop()
