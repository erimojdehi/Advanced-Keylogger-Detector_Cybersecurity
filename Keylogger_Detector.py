import os
import psutil
import time
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext
import pefile
import subprocess

# === Configuration ===
APPDATA = os.getenv("APPDATA")
TEMP = os.getenv("TEMP")
WHITELIST_NAMES = [
    "explorer.exe", "discord.exe", "chrome.exe", "firefox.exe", "spotify.exe",
    "steam.exe", "vscode.exe", "code.exe", "onedrive.exe", "notepad.exe",
    "taskmgr.exe", "pycharm64.exe", "cmd.exe", "WhatsApp.exe", "ms-teams.exe",
    "EpicWebHelper.exe", "steamwebhelper.exe", "AsusOptimizationStartupTask.exe",
    "msedge.exe", "NVIDIA Web Helper.exe", "RadeonSoftware.exe"
]
SUSPICIOUS_DIRS = [APPDATA.lower(), TEMP.lower(), "startup"]
SUSPICIOUS_EXTENSIONS = [".log", ".txt"]
suspicious_processes = []
checkbox_vars = []
checkbox_items = []
stop_scan = False

# ===   LOG FUNCTION DEFINITION ===
def log(text):
    root.after(0, lambda: _safe_log(text))

def _safe_log(text):
    log_output.configure(state='normal')
    log_output.insert(tk.END, text + "\n")
    log_output.see(tk.END)
    log_output.configure(state='disabled')

# === GUI SETUP ===
root = tk.Tk()
root.title("Active Keylogger Detector")
root.geometry("800x700") 

# --- Button Frame
btn_frame = ttk.Frame(root)
btn_frame.pack(fill='x', padx=10, pady=10)

btn = ttk.Button(btn_frame, text="Start Scan", command=lambda: threading.Thread(target=scan_processes, daemon=True).start())
btn.pack(side='left', padx=5)

stop_btn = ttk.Button(btn_frame, text="Stop Scan", command=lambda: stop_scan_trigger())
stop_btn.pack(side='left', padx=5)

# --- Progress Bar + Labels (follows button frame)
top_frame = ttk.Frame(root)
top_frame.pack(fill='x', padx=10, pady=5)
top_frame.configure(height=50)

progress_var = tk.DoubleVar()
progress_bar = ttk.Progressbar(top_frame, variable=progress_var, maximum=100)
progress_bar.pack(fill='x')

percent_label = tk.Label(top_frame, text="Progress: 0%")
percent_label.pack(anchor='w')

time_label = tk.Label(top_frame, text="Total scan time: 0.00s")
time_label.pack(anchor='w', pady=(5, 0))

# --- Scrollable Checkbox Area ---
checkbox_container = ttk.Frame(root)
checkbox_container.pack(fill='x', padx=10, pady=10)

canvas = tk.Canvas(checkbox_container, height=120)
canvas.pack(side='left', fill='x')  # no expand=True

scrollbar = ttk.Scrollbar(checkbox_container, orient='vertical', command=canvas.yview)
scrollbar.pack(side='right', fill='y')

canvas.configure(yscrollcommand=scrollbar.set)

checkbox_frame = ttk.Frame(canvas)
canvas.create_window((0, 0), window=checkbox_frame, anchor='nw')

def _update_scrollregion(event):
    canvas.configure(scrollregion=canvas.bbox("all"))

checkbox_frame.bind("<Configure>", _update_scrollregion)

def _on_mousewheel(event):
    canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

canvas.bind_all("<MouseWheel>", _on_mousewheel)

# --- Log Output Frame ---
log_output = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=18, state='disabled')
log_output.pack(fill='both', expand=True, padx=10, pady=5)

# Auto-resize scroll region
def _update_scrollregion(event):
    canvas.configure(scrollregion=canvas.bbox("all"))


# === Detection Helpers ===
def stop_scanning():
    global stop_scan
    stop_scan = True

def is_suspicious_path(path):
    if not path:
        return False
    return any(suspicious in path.lower() for suspicious in SUSPICIOUS_DIRS)

def is_whitelisted(name):
    return name.lower() in [n.lower() for n in WHITELIST_NAMES]

def is_signed(path):
    try:
        if os.path.getsize(path) > 20 * 1024 * 1024:
            return True
        pe = pefile.PE(path)
        for entry in pe.DIRECTORY_ENTRY_SECURITY:
            return True
    except Exception:
        pass
    return False

def process_has_log_behavior(proc):
    try:
        for f in proc.open_files():
            if any(f.path.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
                return True
    except Exception:
        pass
    return False

def is_headless(proc):
    try:
        parent = proc.parent()
        if parent and parent.name().lower() in ["explorer.exe", "cmd.exe"]:
            return False
    except Exception:
        pass
    return True

# === Scanner === 
def scan_processes():
    global stop_scan
    try:
        stop_scan = False
        suspicious_processes.clear()
        log("=== Scan started ===")
        start_time = time.perf_counter()
        all_procs = list(psutil.process_iter(['pid', 'name', 'exe', 'cwd']))
        total = len(all_procs)

        for i, proc in enumerate(all_procs):
            if stop_scan:
                log("[!] Scan manually stopped by user.")
                break

            try:
                name = proc.info['name']
                exe_path = proc.info['exe'] or ""

                log(f"[Scanning:] {name} | PID: {proc.pid} | Path: {exe_path}")

                if not name or is_whitelisted(name):
                    continue

                score = 0
                if is_suspicious_path(exe_path):
                    score += 1
                if process_has_log_behavior(proc):
                    score += 1
                if is_headless(proc):
                    score += 1
                if not is_signed(exe_path):
                    score += 1

                try:
                    exe_dir = os.path.dirname(exe_path)
                    if exe_dir and os.path.exists(exe_dir):
                        for filename in os.listdir(exe_dir):
                            if filename.endswith(".txt") or filename.endswith(".log"):
                                file_path = os.path.join(exe_dir, filename)
                                mtime = os.path.getmtime(file_path)
                                age = time.time() - mtime
                                if age < 60:
                                    score += 1
                                    log(f"[+] Detected recent log file in {exe_dir}: {filename}")
                                    break
                except Exception as e:
                    log(f"[DEBUG] Log file age check failed for {name}: {e}")

                exe_dir = os.path.dirname(exe_path).lower()
                for f in proc.open_files():
                    file_path = f.path.lower()
                    if any(file_path.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
                        if os.path.dirname(file_path).lower() == exe_dir:
                            score += 1
                            log(f"[+] Local logging behavior detected: {name} is writing to a .txt/log in its own folder")
                            break

                try:
                    exe_dir = os.path.dirname(exe_path)
                    if exe_dir and os.path.exists(exe_dir):
                        for filename in os.listdir(exe_dir):
                            if filename.endswith(".txt") or filename.endswith(".log"):
                                file_path = os.path.join(exe_dir, filename)
                                mtime = os.path.getmtime(file_path)
                                size = os.path.getsize(file_path)
                                age = time.time() - mtime
                                if age < 10 and size > 0:
                                    score += 1
                                    log(f"[+] Live file logging detected: {filename} recently modified ({int(age)}s ago, {size} bytes)")
                                    break
                except Exception as e:
                    log(f"[DEBUG] Real-time file check failed for {name}: {e}")

                if score >= 3:
                    suspicious_processes.append((proc, exe_path))
                    log(f"[!] Suspicious: {name} (PID: {proc.pid})")
                    log(f"    → Path: {exe_path}")
                    log(f"    → Suspicious Score: {score}/4\n")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            progress = ((i + 1) / total) * 100
            progress_var.set(progress)
            percent_label.config(text=f"Progress: {int(progress)}%")
            time_label.config(text=f"Total scan time: {time.perf_counter() - start_time:.2f}s")
            root.update()

            if not suspicious_processes:
                log("[✓] No active keylogger-like processes found.")
            else:
                log(f"\n[!] Total suspicious processes: {len(suspicious_processes)}")
                log("[!] Select which processes to delete below:\n")

                checkbox_vars.clear()
                checkbox_items.clear()
                for widget in checkbox_frame.winfo_children():
                    widget.destroy()

                for i, (proc, path) in enumerate(suspicious_processes, 1):
                    var = tk.IntVar()
                    checkbox_vars.append(var)
                    checkbox_items.append((proc, path))

                    chk = ttk.Checkbutton(checkbox_frame, text=f"{i}. {proc.name()} (PID: {proc.pid})", variable=var)
                    chk.pack(anchor='w', pady=2)

        log("=== Scan complete ===")

    except Exception as e:
        log(f"[ERROR] {e}")

def cleanup_suspicious():
    any_selected = False

    for idx, (proc, path) in enumerate(checkbox_items):
        if checkbox_vars[idx].get():
            any_selected = True
            try:
                proc.kill()
                log(f"[+] Killed process: {proc.name()} (PID: {proc.pid})")
            except Exception as e:
                log(f"[!] Failed to kill process {proc.name()}: {e}")

            try:
                os.remove(path)
                log(f"[+] Deleted file: {path}")
            except Exception as e:
                log(f"[!] Failed to delete file {path}: {e}")

    if not any_selected:
        log("[!] No processes were selected for removal.")
    else:
        log("\n[✓] Selected cleanup complete.")

cleanup_btn = ttk.Button(btn_frame, text="Delete Selected Processes", command=cleanup_suspicious)
cleanup_btn.pack(side='left', padx=5)


stop_scan = False
def stop_scan_trigger():
    global stop_scan
    stop_scan = True

root.mainloop()
