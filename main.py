import os
import csv
import time
import psutil
import pyautogui
import pyperclip
import win32gui
import win32process
import socket
from pynput import keyboard, mouse
from threading import Thread
import re

# **User-defined whitelisted processes**
WHITELISTED_PROCESSES = []
def get_user_whitelisted_processes():
    global WHITELISTED_PROCESSES
    processes = input("Enter whitelisted processes (comma-separated, e.g., code.exe, python.exe): ")
    WHITELISTED_PROCESSES = [proc.strip().lower() for proc in processes.split(",")]
    print(f"Whitelisted Processes: {WHITELISTED_PROCESSES}")

get_user_whitelisted_processes()

# **Logging setup**
CSV_FILE = "activity_log.csv"
HEADERS = ["Timestamp", "Event", "Process Name", "Window Handle", "Window Title", "IP Address", "Domain Name", "Action Taken"]

if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(HEADERS)

# **Critical System Processes (Never Terminate)**
CRITICAL_SYSTEM_PROCESSES = [
    "explorer.exe", "winlogon.exe", "taskmgr.exe",
    "csrss.exe", "services.exe", "svchost.exe", "lsass.exe",
    "dwm.exe", "system", "smss.exe", "textinputhost.exe"
]

# **Global Variables**
last_clipboard_content = ""
last_window_handle = None
last_window_title = None

# **Function to check if a process has an open (visible) window**
def is_process_visible(pid):
    def callback(hwnd, visible_windows):
        if hwnd and win32gui.IsWindowVisible(hwnd):
            try:
                _, process_id = win32process.GetWindowThreadProcessId(hwnd)
                if process_id == pid:
                    visible_windows.append(True)
            except:
                pass
    visible_windows = []
    win32gui.EnumWindows(callback, visible_windows)
    return bool(visible_windows)

# **Screenshot Function**
def take_screenshot(process_name, window_handle, window_title, reason):
    if reason in ["Tab Switch Detected", "Unauthorized Process Detected", "Clipboard Activity Detected", "Suspicious Keystroke"]:
        timestamp = time.strftime('%Y%m%d_%H%M%S')

        # **Sanitize window title to remove invalid filename characters**
        safe_window_title = re.sub(r'[\/:*?"<>|]', '_', window_title)[:50]  # Limit length to 50 chars

        # **Ensure screenshots folder exists**
        os.makedirs("screenshots", exist_ok=True)

        # **Generate filename**
        filename = f"screenshots/{process_name}-{safe_window_title}-{reason}-{timestamp}.png"

        # **Take & Save Screenshot**
        screenshot = pyautogui.screenshot()
        screenshot.save(filename)

        # **Log Screenshot Event**
        log_event("Screenshot Taken", process_name, window_handle, window_title, "", "", reason)

# **Logging Function**
def log_event(event, process_name="", window_handle="", window_title="", ip_address="", domain="", action_taken=""):
    timestamp = time.strftime('%d-%m-%Y %H:%M:%S')
    with open(CSV_FILE, mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, event, process_name, window_handle, window_title, ip_address, domain, action_taken])
    print(f"[{timestamp}] {event} | Process: {process_name} | Handle: {window_handle} | Window: {window_title} | IP: {ip_address} | Domain: {domain} | Action: {action_taken}")

# **Process Monitoring & Termination**
def monitor_processes():
    while True:
        for process in psutil.process_iter(['pid', 'exe', 'name']):
            try:
                process_path = process.info.get('exe', None)
                process_name = process.info.get('name', "").lower()
                process_pid = process.info['pid']
                process_real_name = os.path.basename(process_path).lower() if process_path else process_name

                if process_real_name in CRITICAL_SYSTEM_PROCESSES or process_real_name in WHITELISTED_PROCESSES:
                    continue

                if not is_process_visible(process_pid):
                    continue  

                log_event("Unauthorized Process Detected", process_real_name, "", "", "", "", "Terminated")
                take_screenshot(process_real_name, "", "", "Unauthorized Process Detected")
                psutil.Process(process_pid).terminate()
                time.sleep(1)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        time.sleep(2)

# **Clipboard Monitoring**
def monitor_clipboard():
    global last_clipboard_content
    while True:
        try:
            clipboard_content = pyperclip.paste()
            if clipboard_content and clipboard_content != last_clipboard_content:
                last_clipboard_content = clipboard_content
                process_name, window_handle, window_title = get_active_window()
                log_event("Clipboard Used", process_name, window_handle, window_title, "", "", f"Copied: {clipboard_content[:30]}...")
                take_screenshot(process_name, window_handle, window_title, "Clipboard Activity Detected")
        except Exception as e:
            print(f"Clipboard Monitoring Error: {str(e)}")
        time.sleep(1)

# **Tab Switch Detection**
# **Tab Switch & Window Switch Detection (Multi-tab Apps)**
# **Enhanced Universal Tab & Window Switch Detection**
# Global Variables
last_window_handle = None
last_window_title = None
last_process_name = None
known_windows = {}

def detect_tab_switches():
    global last_window_handle, last_window_title, last_process_name, known_windows

    while True:
        process_name, window_handle, window_title = get_active_window()

        # Ensure we have initialized values
        if last_process_name is None:
            last_process_name = process_name
        if last_window_handle is None:
            last_window_handle = window_handle
        if last_window_title is None:
            last_window_title = window_title

        # **Detect a new app window (window switch)**
        if process_name != last_process_name:
            log_event("Window Switch Detected", process_name, window_handle, window_title, "", "", "Suspicious Activity")
            take_screenshot(process_name, window_handle, window_title, "Window Switch Detected")

        # **Detect tab switches within the same app**
        elif process_name in known_windows:  
            if window_title not in known_windows[process_name]:  # If a new tab appears
                log_event("Tab Switch Detected", process_name, window_handle, window_title, "", "", "Suspicious Activity")
                take_screenshot(process_name, window_handle, window_title, "Tab Switch Detected")
                known_windows[process_name].append(window_title)  # Track opened tabs
        else:
            known_windows[process_name] = [window_title]  # Initialize tracking

        # **Update last known values**
        last_window_handle = window_handle
        last_window_title = window_title
        last_process_name = process_name

        time.sleep(0.5)  # Faster detection


# **Get Active Window Process Name**
def get_active_window():
    try:
        hwnd = win32gui.GetForegroundWindow()
        if hwnd == 0:
            return None, None, None
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        process = psutil.Process(pid)
        process_name = process.name().lower()
        window_title = win32gui.GetWindowText(hwnd)
        return process_name, hwnd, window_title
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None, None, None

# **Network Monitoring**
def monitor_network():
    while True:
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip = conn.raddr.ip
                    domain = get_domain_from_ip(remote_ip)
                    process_name, window_handle, window_title = get_active_window()
                    log_event("Network Activity", process_name, window_handle, window_title, remote_ip, domain, "Monitoring")
        except Exception as e:
            print(f"Network Monitoring Error: {str(e)}")
        time.sleep(5)

# **Resolve IP to Domain Name**
def get_domain_from_ip(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "Unknown"

# **Keyboard & Mouse Event Handling**
def on_key_press(key):
    process_name, window_handle, window_title = get_active_window()
    log_event("Key Pressed", process_name, window_handle, window_title, "", "", f"Key: {key}")

def on_click(x, y, button, pressed):
    if pressed:
        process_name, window_handle, window_title = get_active_window()
        log_event("Mouse Click", process_name, window_handle, window_title, "", "", f"Button: {button}")

# **Start Monitoring**
def start_monitoring():
    log_event("Monitoring Started", "", "", "", "", "", "System Initialized")
    
    threads = [
        Thread(target=monitor_processes, daemon=True),
        Thread(target=monitor_clipboard, daemon=True),
        Thread(target=detect_tab_switches, daemon=True),
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
