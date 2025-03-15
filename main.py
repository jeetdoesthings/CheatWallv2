import os
import csv
import time
import psutil
import pyautogui
import pyperclip
import win32gui
import win32process
import ctypes
import socket
from pynput import keyboard, mouse
from threading import Thread

# Get user-defined whitelisted processes
WHITELISTED_PROCESSES = []
def get_user_whitelisted_processes():
    global WHITELISTED_PROCESSES
    processes = input("Enter whitelisted processes (comma-separated, e.g., notepad.exe, python.exe): ")
    WHITELISTED_PROCESSES = [proc.strip().lower() for proc in processes.split(",")]
    print(f"Whitelisted Processes: {WHITELISTED_PROCESSES}")

get_user_whitelisted_processes()

# Logging setup
CSV_FILE = "student_activity_log.csv"
NETWORK_LOG_FILE = "network_activity_log.csv"

HEADERS = ["Timestamp", "Event", "Process Name", "Window Handle", "Remote IP", "Action Taken"]
NETWORK_HEADERS = ["Timestamp", "Process Name", "IP Address", "Domain Name", "Action Taken"]

if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(HEADERS)

if not os.path.exists(NETWORK_LOG_FILE):
    with open(NETWORK_LOG_FILE, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(NETWORK_HEADERS)

# List of critical system processes that should NOT be terminated
CRITICAL_SYSTEM_PROCESSES = [
    "explorer.exe", "winlogon.exe", "taskmgr.exe",
    "csrss.exe", "services.exe", "svchost.exe", "lsass.exe",
    "dwm.exe", "system", "smss.exe"
]

# Function to check if a process has an open (visible) window
def is_process_visible(pid):
    """Returns True if the process has a visible window."""
    def callback(hwnd, visible_windows):
        if hwnd and win32gui.IsWindowVisible(hwnd):  # Ensure hwnd is valid
            try:
                _, process_id = win32gui.GetWindowThreadProcessId(hwnd)
                if process_id == pid:
                    visible_windows.append(True)
            except:
                pass  # Ignore invalid window handles

    visible_windows = []
    win32gui.EnumWindows(callback, visible_windows)
    return bool(visible_windows)  # Returns True if any window is visible for this process

# Screenshot on suspicious activity
def take_screenshot(reason):
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    filename = f"screenshots/screenshot_{timestamp}.png"
    os.makedirs("screenshots", exist_ok=True)
    screenshot = pyautogui.screenshot()
    screenshot.save(filename)
    log_event("Screenshot Taken", reason)

# Log events
def log_event(event, process_name="", window_handle="", remote_ip="", action_taken=""):
    timestamp = time.strftime('%d-%m-%Y %H:%M:%S')
    with open(CSV_FILE, mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, event, process_name, window_handle, remote_ip, action_taken])
    print(f"[{timestamp}] {event} | Process: {process_name} | Window Handle: {window_handle} | Action: {action_taken}")

# Log network activity
def log_network_event(process_name, ip, domain, action):
    timestamp = time.strftime('%d-%m-%Y %H:%M:%S')
    with open(NETWORK_LOG_FILE, mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, process_name, ip, domain, action])
    print(f"[{timestamp}] Network Activity | Process: {process_name} | IP: {ip} | Domain: {domain} | Action: {action}")

# Get active window's process name
def get_active_window():
    try:
        hwnd = win32gui.GetForegroundWindow()
        if hwnd == 0:  # No active window
            return None, None
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        process = psutil.Process(pid)
        process_name = process.name().lower()
        return process_name, hwnd
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None, None

# Detect Tab Switching (Chrome, VS Code, Browsers)
last_window_handle = None
last_window_title = None
def detect_tab_switches():
    global last_window_handle, last_window_title
    while True:
        hwnd = win32gui.GetForegroundWindow()
        window_title = win32gui.GetWindowText(hwnd)

        if hwnd != last_window_handle and window_title != last_window_title:
            log_event("Tab Switch Detected", action_taken="Suspicious Activity")
            take_screenshot("Tab Switch Detected")
            last_window_handle = hwnd
            last_window_title = window_title

        time.sleep(1)

# Detect Desktop Switching
def detect_desktop_switch():
    last_desktop = ctypes.windll.user32.GetThreadDesktop(ctypes.windll.kernel32.GetCurrentThreadId())
    while True:
        current_desktop = ctypes.windll.user32.GetThreadDesktop(ctypes.windll.kernel32.GetCurrentThreadId())
        if current_desktop != last_desktop:
            log_event("Desktop Switch Detected", action_taken="Suspicious Desktop Switch")
            take_screenshot("Desktop Switch Detected")
            last_desktop = current_desktop
        time.sleep(1)
# Function to resolve IP to domain name
def get_domain_from_ip(ip):
    try:
        return socket.gethostbyaddr(ip)[0]  # Reverse DNS lookup
    except (socket.herror, socket.gaierror):
        return "Unknown"  # If lookup fails, return "Unknown"

# Network Monitoring for All Open Windows
# System processes to ignore in network logging
SYSTEM_PROCESSES_TO_IGNORE = ["svchost.exe", "lockapp.exe", "explorer.exe", "taskmgr.exe"]

def monitor_network():
    while True:
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip = conn.raddr.ip
                    domain = get_domain_from_ip(remote_ip)

                    try:
                        process = psutil.Process(conn.pid)
                        process_name = process.name().lower()

                        # Ignore system processes
                        if process_name in SYSTEM_PROCESSES_TO_IGNORE:
                            continue  

                        log_network_event(process_name, remote_ip, domain, "Monitoring")

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

        except Exception as e:
            print(f"Network Monitoring Error: {str(e)}")
        time.sleep(5)

# Process Monitoring & Termination
def monitor_processes():
    while True:
        for process in psutil.process_iter(['pid', 'name']):
            try:
                process_name = process.info['name'].lower()
                process_pid = process.info['pid']

                # Ignore system background processes
                if process_name in CRITICAL_SYSTEM_PROCESSES:
                    continue

                # Check if process has an open window before terminating
                if not is_process_visible(process_pid):
                    continue  # Skip processes that don't have open windows

                # If it's not whitelisted, terminate it
                if process_name not in WHITELISTED_PROCESSES:
                    log_event("Unauthorized Process Detected", process_name, action_taken="Terminated")
                    take_screenshot(f"Unauthorized Process Detected: {process_name}")
                    psutil.Process(process_pid).kill()

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        time.sleep(2)  # Prevent high CPU usage

# Keyboard Monitoring
def on_key_press(key):
    log_event("Key Pressed", action_taken=f"{key}")

# Mouse Monitoring
def on_click(x, y, button, pressed):
    if pressed and button == mouse.Button.right:
        log_event("Mouse Right Click", action_taken="Suspicious Right-Click Paste")
        take_screenshot("Mouse Right Click Detected")

# Start Monitoring
def start_monitoring():
    log_event("Monitoring Started", action_taken="System Initialized")
    
    threads = [
        Thread(target=detect_tab_switches, daemon=True),
        Thread(target=detect_desktop_switch, daemon=True),
        Thread(target=monitor_processes, daemon=True),
        Thread(target=monitor_network, daemon=True),
    ]
    for thread in threads:
        thread.start()

    with keyboard.Listener(on_press=on_key_press) as key_listener, \
         mouse.Listener(on_click=on_click) as mouse_listener:
        key_listener.join()
        mouse_listener.join()

if __name__ == '__main__':
    print("\nStarting Student Proctoring System...\n")
    start_monitoring()
