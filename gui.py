import os
import sys
import tkinter as tk
from tkinter import messagebox
import subprocess
import threading
import time

# Add the current directory to Python path
if getattr(sys, 'frozen', False):
    # If the application is run as a bundle
    bundle_dir = sys._MEIPASS
else:
    # If the application is run from a Python interpreter
    bundle_dir = os.path.dirname(os.path.abspath(__file__))

sys.path.append(bundle_dir)

# Import main module without executing its top-level code
import importlib.util
spec = importlib.util.spec_from_file_location("main", os.path.join(bundle_dir, "main.py"))
main = importlib.util.module_from_spec(spec)
sys.modules["main"] = main
spec.loader.exec_module(main)

# Override the user input function to use GUI input instead
def get_gui_whitelisted_processes():
    # Add the executable name to the whitelist to prevent self-termination
    exe_name = os.path.basename(sys.executable).lower() if getattr(sys, 'frozen', False) else "python.exe"
    if exe_name not in main.WHITELISTED_PROCESSES:
        main.WHITELISTED_PROCESSES.append(exe_name)
    return main.WHITELISTED_PROCESSES

# Replace the console input function with our GUI version
main.get_user_whitelisted_processes = get_gui_whitelisted_processes

# ✅ GUI Initialization
root = tk.Tk()
root.title("Student Proctoring System")
root.geometry("500x400")

# ✅ Global Variables
exam_started = False
timer_label = None
timer_thread = None
exam_duration = 0  # Duration in seconds (set by admin)

# ✅ User Inputs
tk.Label(root, text="Username:").pack(pady=5)
username_entry = tk.Entry(root)
username_entry.pack()

tk.Label(root, text="Exam Code:").pack(pady=5)
exam_code_entry = tk.Entry(root)
exam_code_entry.pack()

# ✅ Timer Function
def start_timer(duration):
    def update_timer(remaining):
        if remaining > 0 and exam_started:
            mins, secs = divmod(remaining, 60)
            timer_label.config(text=f"Time Remaining: {mins:02}:{secs:02}")
            root.after(1000, update_timer, remaining - 1)  # Schedule the next update
        elif exam_started:
            timer_label.config(text="Time's up!")
            messagebox.showinfo("Time's Up", "The exam time has ended.")
            end_exam()

    update_timer(duration)  # Start the timer

# ✅ Open Exam App Function
def open_exam_app():
    # Get the base directory for the executable
    if getattr(sys, 'frozen', False):
        base_dir = sys._MEIPASS
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        
    # Fetch the whitelisted exam apps from main
    exam_apps = main.WHITELISTED_PROCESSES

    if not exam_apps:
        messagebox.showerror("Error", "No whitelisted exam apps are configured. Please contact the admin.")
        return

    # Attempt to open all whitelisted apps that aren't system processes
    failed_apps = []
    opened_apps = []
    system_processes = ["explorer.exe", "winlogon.exe", "csrss.exe", "services.exe", 
                      "svchost.exe", "lsass.exe", "dwm.exe", "system", "smss.exe"]
    
    for app in exam_apps:
        if app.lower() in system_processes:
            continue
            
        try:
            # Only try to open regular applications, not system processes
            app_path = os.path.join(base_dir, app)
            if os.path.exists(app_path):
                subprocess.Popen([app_path], shell=True)
                opened_apps.append(app)
            else:
                # Try to open using just the app name (system path)
                subprocess.Popen([app], shell=True)
                opened_apps.append(app)
        except Exception as e:
            failed_apps.append(f"{app} ({str(e)})")

    if opened_apps:
        messagebox.showinfo("Exam Apps Opened", f"The following exam apps have been opened: {', '.join(opened_apps)}")
    
    if failed_apps:
        messagebox.showerror(
            "Error",
            f"The following exam apps could not be opened: {', '.join(failed_apps)}. Please contact the admin."
        )

# ✅ Start Exam Function
def start_exam():
    global exam_started, timer_label, exam_duration

    username = username_entry.get().strip()
    exam_code = exam_code_entry.get().strip()

    if not username or not exam_code:
        messagebox.showerror("Error", "Please enter username and exam code!")
        return

    # Add our own executable to the whitelist to prevent self-termination
    if getattr(sys, 'frozen', False):
        exe_name = os.path.basename(sys.executable).lower()
        if exe_name not in main.WHITELISTED_PROCESSES:
            main.WHITELISTED_PROCESSES.append(exe_name)
    else:
        if "python.exe" not in main.WHITELISTED_PROCESSES:
            main.WHITELISTED_PROCESSES.append("python.exe")
    
    # Display the current whitelist
    messagebox.showinfo("Whitelisted Processes", 
                       f"The following processes are whitelisted:\n\n{', '.join(main.WHITELISTED_PROCESSES)}")

    # Consent for logging user data
    consent = messagebox.askyesno("Consent", "Do you consent to the monitoring and logging of your activities during the exam?")
    if not consent:
        messagebox.showwarning("Consent Denied", "You must consent to proceed with the exam.")
        return

    # Set the exam duration (in seconds) for example, 1 hour (can be changed based on the admin input)
    exam_duration = 3600  # 1 hour

    # Start Exam
    exam_started = True
    messagebox.showinfo("Exam Started", f"The exam has started. Good luck, {username}!")

    # Enable the Open Exam App button once exam is started
    open_exam_button.config(state=tk.NORMAL)

    # Open Notepad (specific app)
    try:
        subprocess.Popen(["notepad.exe"], shell=True)
        messagebox.showinfo("Exam App Opened", "Notepad has been opened for the exam.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open Notepad: {str(e)}")

    # Start the monitoring system in a new thread to run in parallel with the GUI
    threading.Thread(target=main.start_monitoring, daemon=True).start()

    # Start the countdown timer
    timer_label = tk.Label(root, text="Time Remaining: 01:00:00", font=("Helvetica", 14))
    timer_label.pack(pady=20)
    start_timer(exam_duration)

# ✅ End Exam Function
def end_exam():
    global exam_started
    if not exam_started:
        messagebox.showerror("Error", "No exam is currently running.")
        return

    confirm = messagebox.askyesno("End Exam", "Are you sure you want to end the exam?")
    if confirm:
        exam_started = False
        messagebox.showinfo("Exam Ended", "The exam has ended. Thank you for your participation.")
        
        # Disable the Open Exam App button after exam ends
        open_exam_button.config(state=tk.DISABLED)
        
        # Option to close the application
        close = messagebox.askyesno("Close Application", "Would you like to close the application?")
        if close:
            root.destroy()  # Close the GUI window

# ✅ Handle Window Close Event
def on_close():
    if exam_started:
        confirm = messagebox.askyesno(
            "Warning",
            "Closing this window will end the exam immediately. Are you sure you want to proceed?"
        )
        if confirm:
            root.destroy()
    else:
        root.destroy()

# ✅ Buttons
start_button = tk.Button(root, text="Start Exam", command=start_exam)
start_button.pack(pady=10)

open_exam_button = tk.Button(root, text="Open Exam App", command=open_exam_app, state=tk.DISABLED)
open_exam_button.pack(pady=10)

end_button = tk.Button(root, text="End Exam", command=end_exam)
end_button.pack(pady=10)

# ✅ Bind Close Event
root.protocol("WM_DELETE_WINDOW", on_close)

# ✅ Main GUI Loop
if __name__ == "__main__":
    root.mainloop()
