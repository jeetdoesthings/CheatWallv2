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
import threading
import re
# Removed tldextract as it's no longer used
from risk_score import risk_queue, warning_queue
from tkinter import messagebox
from risk_score import start_risk_monitoring, risk_queue
import queue
event_stream = queue.Queue()
from PIL import ImageGrab
import ctypes
import ctypes.wintypes

# ✅ User-defined whitelisted processes (converted to lowercase)
WHITELISTED_PROCESSES = [
    "windowsterminal.exe", "openconsole.exe", "gui.exe", "code.exe", 
    "notepad.exe", "chrome.exe", "python3.11.exe"
]

# ✅ Critical System Processes (Never Terminate)
CRITICAL_SYSTEM_PROCESSES = [
    "explorer.exe", "winlogon.exe", "taskmgr.exe", "csrss.exe", "services.exe",
    "svchost.exe", "lsass.exe", "dwm.exe", "system", "smss.exe", "textinputhost.exe",
    "svchost.exe", "searchhost.exe", "mpdefendercoreservice.exe",
    "dllhost.exe", "runtimebroker.exe", "services.exe",
    "lsass.exe", "smss.exe", "csrss.exe", "wininit.exe"
]

# ✅ Logging setup
CSV_FILE = "activity_log.csv"
HEADERS = [
    "Timestamp", "Event Type", "Process Name", 
    "Window Handle", "Window Title", 
    "IP Address", "Domain Name", "Action Taken"
]

if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(HEADERS)

def get_current_desktop_number():
    try:
        hDesk = ctypes.windll.user32.GetThreadDesktop(ctypes.windll.kernel32.GetCurrentThreadId())
        VIEW_OFFSET = 0x88  # Windows 10+ offset for desktop number
        buffer = ctypes.create_string_buffer(4)
        ctypes.windll.ntdll.NtQueryInformationProcess(
            -1, 0x26, buffer, 4, None  # ProcessDesktopInformation
        )
        return int.from_bytes(buffer.raw, byteorder='little')
    except:
        return 1

# Add these functions before start_monitoring()

def on_key_press(key):
    try:
        key_str = key.char
    except AttributeError:
        key_str = str(key).split('.')[-1]
    
    process_name, hwnd, window_title = get_active_window()
    log_event(
        "Keyboard Input",
        process_name,
        hwnd,
        window_title,
        action_taken=f"Key pressed: {key_str}"
    )

def on_mouse_click(x, y, button, pressed):
    if pressed:
        process_name, hwnd, window_title = get_active_window()
        log_event(
            "Mouse Activity",
            process_name,
            hwnd,
            window_title,
            action_taken=f"{button.name.capitalize()} click at ({x}, {y})"
        )

def start_input_monitoring():
    """Start monitoring keyboard and mouse inputs"""
    keyboard_listener = keyboard.Listener(on_press=on_key_press)
    mouse_listener = mouse.Listener(on_click=on_mouse_click)
    
    keyboard_listener.start()
    mouse_listener.start()
    
    # Keep references to prevent garbage collection
    while True:
        time.sleep(1)

# ✅ Log event function
def log_event(event, process_name="", window_handle=None, window_title=None, ip_address="", domain="", action_taken=""):
    """Logs all system activities in a CSV file and prints them to the console."""
    timestamp = time.strftime('%d-%m-%Y %H:%M:%S')

    # ✅ Ensure window handle and title are always fetched
    if window_handle is None or window_title is None:
        process_name, window_handle, window_title = get_active_window()

    with open(CSV_FILE, mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, event, process_name, window_handle, window_title, ip_address, domain, action_taken])

    print(f"[{timestamp}] {event} | Process: {process_name} | Handle: {window_handle} | Window: {window_title} | IP: {ip_address} | Domain: {domain} | Action: {action_taken}")

def is_process_visible(pid):
    """Check if the process has an open (visible) window."""
    def callback(hwnd, visible_windows):
        if hwnd and win32gui.IsWindowVisible(hwnd):
            try:
                _, process_id = win32process.GetWindowThreadProcessId(hwnd)
                if process_id == pid:
                    visible_windows.append(hwnd)
            except:
                pass
    visible_windows = []
    win32gui.EnumWindows(callback, visible_windows)
    return bool(visible_windows)

def monitor_processes():
    """Terminate only unauthorized processes that have a visible window."""
    while True:
        for process in psutil.process_iter(['pid', 'name']):
            try:
                process_name = process.info['name'].lower()
                process_pid = process.info['pid']

                # ✅ Ignore critical system processes
                if process_name in [p.lower() for p in CRITICAL_SYSTEM_PROCESSES]:
                    continue

                # ✅ Ignore whitelisted processes
                if process_name in [p.lower() for p in WHITELISTED_PROCESSES]:
                    continue

                # ✅ Only terminate processes with an open (visible) window
                if is_process_visible(process_pid):
                    process_name, window_handle, window_title = get_active_window()
                    log_event("Unauthorized Process Detected", process_name, window_handle, window_title, "", "", "Terminated")
                    log_suspicious_activity("Unauthorized Process")
                    psutil.Process(process_pid).terminate()

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

def detect_tab_switches():
    global last_window_handle, last_window_title
    setup_screenshots()
    last_desktop = get_current_desktop_number()
    
    while True:
        try:
            current_desktop = get_current_desktop_number()
            if current_desktop != last_desktop:
                take_screenshot("desktop_switch")
                log_event("Desktop Switch", "", "", "", "", "", "Suspicious Activity")
                last_desktop = current_desktop
            
            process_name, window_handle, window_title = get_active_window()
            
            if window_handle != last_window_handle or window_title != last_window_title:
                take_screenshot("tab_switch")
                log_event(
                    "Tab Switch Detected",
                    process_name,
                    window_handle,
                    window_title,
                    action_taken="Suspicious Activity"
                )
                
            last_window_handle = window_handle
            last_window_title = window_title
            
        except Exception as e:
            print(f"Tab switch error: {str(e)}")

def get_domain_from_ip(ip_address):
    """Return the full domain name from a given IP address using DNS lookup"""
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except (socket.herror, socket.gaierror):
        return ip_address  # Return IP if resolution fails

def monitor_network():
    """Network monitoring using DNS lookup for domain names.
       Logs new connections (based on IP, port, and PID) so that persistent connections aren’t repeatedly logged.
    """
    seen_connections = set()
    while True:
        try:
            current_proc, hwnd, window_title = get_active_window()
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    try:
                        process = psutil.Process(conn.pid)
                        proc_name = process.name().lower()
                        
                        # Skip critical system processes
                        if proc_name in CRITICAL_SYSTEM_PROCESSES:
                            continue
                            
                        remote_ip = conn.raddr[0]
                        remote_port = conn.raddr[1]
                        
                        # Use DNS lookup to get the domain name (always do this)
                        domain = get_domain_from_ip(remote_ip)
                        
                        # Create a unique key for this connection
                        key = (remote_ip, remote_port, conn.pid)
                        if key not in seen_connections:
                            seen_connections.add(key)
                            log_event(
                                "Network Connection",
                                proc_name,
                                hwnd,
                                window_title,
                                f"{remote_ip}:{remote_port}",
                                domain,
                                "Monitoring"
                            )
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
        except Exception as e:
            print(f"Network Error: {str(e)}")
        time.sleep(1)

last_window_handle = None
last_window_title = None

def monitor_clipboard():
    global last_clipboard_content
    last_clipboard_content = ""  # Initialize the variable
    setup_screenshots()
    while True:
        try:
            clipboard_content = pyperclip.paste()
            if clipboard_content and clipboard_content != last_clipboard_content:
                last_clipboard_content = clipboard_content
                process_name, window_handle, window_title = get_active_window()
                log_event("Clipboard Used", process_name, window_handle, window_title, "", "", "Suspicious Activity")
                log_suspicious_activity("Clipboard Paste")
                take_screenshot("clipboard")  # Add screenshot
        except Exception as e:
            print(f"Clipboard error: {str(e)}")

# ✅ Get Active Window Process Name
def get_active_window():
    """Returns the currently active window's process name, handle, and title."""
    try:
        hwnd = win32gui.GetForegroundWindow()
        if hwnd == 0:
            return "Unknown", None, "Unknown Window"

        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        process = psutil.Process(pid)
        process_name = process.name().lower()
        window_title = win32gui.GetWindowText(hwnd)

        return process_name, hwnd, window_title
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "Unknown", None, "Unknown Window"
    
def log_suspicious_activity(event_type):
    """Send detected events to the risk scoring system."""
    event_stream.put(event_type)

SCREENSHOT_DIR = "screenshots"
SCREENSHOT_COUNTER = 0

def setup_screenshots():
    """Create screenshot directory if not exists"""
    if not os.path.exists(SCREENSHOT_DIR):
        os.makedirs(SCREENSHOT_DIR)
    global SCREENSHOT_COUNTER
    SCREENSHOT_COUNTER = len(os.listdir(SCREENSHOT_DIR)) if os.path.exists(SCREENSHOT_DIR) else 0

def take_screenshot(reason):
    """Capture screenshot of active window with timestamp"""
    global SCREENSHOT_COUNTER
    try:
        # Get active window dimensions
        hwnd = win32gui.GetForegroundWindow()
        rect = win32gui.GetWindowRect(hwnd)
        
        # Capture only the active window
        screenshot = ImageGrab.grab(rect)
        
        # Generate filename
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"{SCREENSHOT_DIR}/{timestamp}_{reason}_{SCREENSHOT_COUNTER}.png"
        
        screenshot.save(filename)
        SCREENSHOT_COUNTER += 1
        return filename
    except Exception as e:
        print(f"Screenshot failed: {str(e)}")
        return None

# ✅ Start Monitoring
def start_monitoring():
    setup_screenshots()
    log_event("Monitoring Started", "", "", "", "", "", "System Initialized")

    # Start risk monitoring in a separate thread
    start_risk_monitoring(event_stream)

    # Start monitoring functions
    threading.Thread(target=monitor_processes, daemon=True).start()
    threading.Thread(target=monitor_clipboard, daemon=True).start()
    threading.Thread(target=detect_tab_switches, daemon=True).start()
    threading.Thread(target=monitor_network, daemon=True).start()
    threading.Thread(target=start_input_monitoring, daemon=True).start()  

# ✅ Run Monitoring if executed directly
if __name__ == '__main__':
    print("\nStarting Student Proctoring System...\n")
    start_monitoring()
