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
import tldextract
from risk_score import risk_queue, warning_queue
from tkinter import messagebox
from risk_score import start_risk_monitoring, risk_queue
import queue
event_stream = queue.Queue()
from PIL import ImageGrab
import ctypes
import ctypes.wintypes
tld_extractor = tldextract.TLDExtract(include_psl_private_domains=True)

# ✅ User-defined whitelisted processes (converted to lowercase)
WHITELISTED_PROCESSES = [
    "windowsterminal.exe", "openconsole.exe", "gui.exe", "code.exe", 
    "notepad.exe", "chrome.exe", "python3.11.exe"
]

# ✅ Critical System Processes (Never Terminate)
CRITICAL_SYSTEM_PROCESSES = [
    "explorer.exe", "winlogon.exe", "taskmgr.exe", "csrss.exe", "services.exe",
    "svchost.exe", "lsass.exe", "dwm.exe", "system", "smss.exe", "textinputhost.exe"
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

        time.sleep(0.05) 

# ✅ Clipboard Monitoring


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
            
        time.sleep(0.1)

def get_domain_from_ip(ip_address):
    """Improved domain simplification with AWS/GCP detection"""
    try:
        # First try reverse DNS
        domain_name = socket.gethostbyaddr(ip_address)[0]
        extracted = tld_extractor(domain_name)
        
        # Handle AWS/GCP domains
        if 'compute.amazonaws' in domain_name:
            parts = domain_name.split('.')
            return f"{parts[-4]}.{'.'.join(parts[-3:])}" if len(parts) >=4 else domain_name
        if 'googleusercontent' in domain_name:
            return "googleusercontent.com"
        
        # Return simplified domain
        if extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
        return extracted.domain if extracted.domain else ip_address
    except (socket.herror, socket.gaierror):
        return ip_address
    except Exception as e:
        print(f"Domain Error: {str(e)}")
        return ip_address

# Modified network monitoring section
def monitor_network():
    extract = tldextract.extract
    while True:
        try:
            current_process, hwnd, window_title = get_active_window()
            
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    try:
                        process = psutil.Process(conn.pid)
                        remote_ip = conn.raddr[0]
                        remote_port = conn.raddr[1]
                        
                        # Get domain from browser title if possible
                        domain = ""
                        if "chrome.exe" in process.name().lower():
                            if " - Google Chrome" in window_title:
                                url_part = window_title.split(" - Google Chrome")[0]
                                extracted = extract(url_part)
                                domain = f"{extracted.domain}.{extracted.suffix}"
                        elif "firefox.exe" in process.name().lower():
                            if " - Mozilla Firefox" in window_title:
                                url_part = window_title.split(" - Mozilla Firefox")[0]
                                extracted = extract(url_part)
                                domain = f"{extracted.domain}.{extracted.suffix}"
                        
                        # Fallback to DNS lookup
                        if not domain:
                            domain = get_domain_from_ip(remote_ip)

                        # Log network activity separately
                        log_event(
                            "Network Connection",
                            process.name(),
                            hwnd,
                            window_title,
                            f"{remote_ip}:{remote_port}",
                            domain,
                            "Monitoring"
                        )

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

        except Exception as e:
            print(f"Network monitoring error: {str(e)}")
        
        time.sleep(0.5)
      
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
        time.sleep(0.1)

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

def get_domain_from_ip(ip_address):
    """Resolves a domain name from an IP address."""
    try:
        domain_name = socket.gethostbyaddr(ip_address)[0]
        return domain_name
    except socket.herror:
        return "Unknown Domain"

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

# ✅ Run Monitoring if executed directly
if __name__ == '__main__':
    print("\nStarting Student Proctoring System...\n")
    start_monitoring()
