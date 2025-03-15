import os
import csv
import time
import psutil
import pyautogui
import pyperclip
import win32gui
import win32process
from pynput import keyboard, mouse
from threading import Thread

# Get user-defined whitelisted processes (from Task Manager "Details" tab)
WHITELISTED_PROCESSES = []
def get_user_whitelisted_processes():
    global WHITELISTED_PROCESSES
    processes = input("Enter whitelisted processes (comma-separated, e.g., code.exe, python.exe): ")
    WHITELISTED_PROCESSES = [proc.strip().lower() for proc in processes.split(",")]
    print(f"Whitelisted Processes: {WHITELISTED_PROCESSES}")

get_user_whitelisted_processes()

# Logging setup
CSV_FILE = "student_activity_log.csv"
HEADERS = ["Timestamp", "Event", "Process Name", "Action Taken"]

if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(HEADERS)

# Critical System Processes (Not to be terminated)
CRITICAL_SYSTEM_PROCESSES = [
    "explorer.exe", "winlogon.exe", "taskmgr.exe",
    "csrss.exe", "services.exe", "svchost.exe", "lsass.exe",
    "dwm.exe", "system", "smss.exe", "textinputhost.exe"
]

# Global variables for clipboard monitoring
last_clipboard_content = ""

# Check if a process has a visible window
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

# Screenshot on suspicious activity
def take_screenshot(process_name, reason):
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    filename = f"screenshots/{process_name}-{reason}-{timestamp}.png"
    os.makedirs("screenshots", exist_ok=True)
    screenshot = pyautogui.screenshot()
    screenshot.save(filename)
    log_event("Screenshot Taken", process_name, action_taken=reason)

# Log events
def log_event(event, process_name="", action_taken=""):
    timestamp = time.strftime('%d-%m-%Y %H:%M:%S')
    with open(CSV_FILE, mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, event, process_name, action_taken])
    print(f"[{timestamp}] {event} | Process: {process_name} | Action: {action_taken}")

# **Process Monitoring & Termination**
def monitor_processes():
    while True:
        for process in psutil.process_iter(['pid', 'exe', 'name']):  
            try:
                process_path = process.info.get('exe', None)  
                process_name = process.info.get('name', "").lower()
                process_pid = process.info['pid']

                if process_path:
                    process_real_name = os.path.basename(process_path).lower()
                else:
                    process_real_name = process_name

                # Ignore critical system processes
                if process_real_name in CRITICAL_SYSTEM_PROCESSES:
                    continue  

                # Ensure whitelisted processes are never terminated
                if process_real_name in WHITELISTED_PROCESSES:
                    continue  

                # Check if process has an open window before terminating
                if not is_process_visible(process_pid):
                    continue  

                log_event("Unauthorized Process Detected", process_real_name, action_taken="Terminated")
                take_screenshot(process_real_name, "Unauthorized Process Detected")

                proc = psutil.Process(process_pid)
                proc.terminate()
                time.sleep(1)

                if proc.is_running():
                    proc.kill()

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        time.sleep(2)

# Clipboard Monitoring
last_clipboard_content = ""

def monitor_clipboard():
    global last_clipboard_content
    while True:
        try:
            clipboard_content = pyperclip.paste().strip()  # Get clipboard content

            # Detect copy-paste only when content changes
            if clipboard_content and clipboard_content != last_clipboard_content:
                last_clipboard_content = clipboard_content  # Update stored content
                log_event("Clipboard Used", action_taken=f"Copied: {clipboard_content[:30]}...")
                take_screenshot("Clipboard", "Clipboard Activity Detected")

        except Exception as e:
            print(f"Clipboard Monitoring Error: {str(e)}")  # Log clipboard errors

        time.sleep(1)  # Check clipboard every second

# Detect keyboard paste (Ctrl + V)
pressed_keys = set()  # Track currently pressed keys

pressed_keys = set()  # Track currently pressed keys

def on_key_press(key):
    global pressed_keys
    pressed_keys.add(key)  # Track pressed keys

    # Check if Ctrl + V is pressed
    if keyboard.Key.ctrl_l in pressed_keys or keyboard.Key.ctrl_r in pressed_keys:
        if hasattr(key, 'char') and key.char == 'v':  # ✅ Fix applied
            try:
                clipboard_content = pyperclip.paste()
                if clipboard_content:
                    log_event("Clipboard Used", action_taken=f"Pasted: {clipboard_content[:30]}...")
                    take_screenshot("Clipboard", "Clipboard Paste Detected")
            except Exception as e:
                print(f"Clipboard Paste Detection Error: {str(e)}")  # ✅ Log actual error
                log_event("Clipboard Error", action_taken=f"Error: {str(e)}")

def on_key_release(key):
    global pressed_keys
    if key in pressed_keys:
        pressed_keys.remove(key)  # Remove released keys
def on_click(x, y, button, pressed):
    if pressed and button == mouse.Button.right:
        clipboard_content = pyperclip.paste()
        if clipboard_content:
            log_event("Clipboard Used", action_taken=f"Right-Click Pasted: {clipboard_content[:30]}...")
            take_screenshot("Clipboard", "Clipboard Right-Click Paste Detected")
# Detect Tab Switching (Chrome, VS Code, Browsers)
last_window_title = None
last_process_name = None

def detect_tab_switches():
    global last_window_title, last_process_name

    while True:
        hwnd = win32gui.GetForegroundWindow()  # Get the active window handle
        window_title = win32gui.GetWindowText(hwnd)  # Get the title of the active window
        _, pid = win32process.GetWindowThreadProcessId(hwnd)  # Get the process ID
        process_name = psutil.Process(pid).name().lower()  # Get the process name

        # If the process name is a known browser or code editor, detect tab switches
        monitored_apps = ["chrome.exe", "msedge.exe", "firefox.exe", "code.exe", "pycharm64.exe"]

        if process_name in monitored_apps:
            if window_title and window_title != last_window_title:
                log_event("Tab Switch Detected", process_name, action_taken=f"Switched to: {window_title}")
                take_screenshot(process_name, f"Tab Switch - {window_title}")
                
                last_window_title = window_title
                last_process_name = process_name

        time.sleep(1)  # Prevent high CPU usage

# Start Monitoring
def start_monitoring():
    log_event("Monitoring Started", action_taken="System Initialized")
    
    threads = [
    Thread(target=monitor_processes, daemon=True),
    Thread(target=monitor_clipboard, daemon=True),  # ✅ Clipboard monitoring added
    Thread(target=detect_tab_switches, daemon=True),
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
