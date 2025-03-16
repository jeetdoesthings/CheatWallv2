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
import main  # ✅ Import main.py to run its functions

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
        if remaining > 0:
            mins, secs = divmod(remaining, 60)
            timer_label.config(text=f"Time Remaining: {mins:02}:{secs:02}")
            root.after(1000, update_timer, remaining - 1)  # Schedule the next update
        else:
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
        
    # Fetch the whitelisted exam apps from main.py
    exam_apps = main.WHITELISTED_PROCESSES

    if not exam_apps:
        messagebox.showerror("Error", "No whitelisted exam apps are configured. Please contact the admin.")
        return

    # Attempt to open all whitelisted apps
    failed_apps = []
    for app in exam_apps:
        try:
            app_path = os.path.join(base_dir, app)
            subprocess.Popen([app_path], shell=True)
            messagebox.showinfo("Exam App Opened", f"The exam app '{app}' has been opened.")
        except FileNotFoundError:
            failed_apps.append(app)

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

    # Consent for logging user data
    consent = messagebox.askyesno("Consent", "Do you consent to the monitoring and logging of your activities during the exam?")
    if not consent:
        messagebox.showwarning("Consent Denied", "You must consent to proceed with the exam.")
        return

    # Set the exam duration (in seconds) for example, 1 hour (can be changed based on the admin input)
    exam_duration = 3600

    # Start Exam
    exam_started = True
    messagebox.showinfo("Exam Started", f"The exam has started. Good luck, {username}!")

    # Start the monitoring system in a new thread to run in parallel with the GUI
    threading.Thread(target=main.start_monitoring, daemon=True).start()

    # Start the countdown timer
    timer_label = tk.Label(root, text="Time Remaining: 01:00", font=("Helvetica", 14))
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
        messagebox.showinfo("Exam Ended", "The exam has ended.")
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
start_button.pack(pady=20)

open_exam_button = tk.Button(root, text="Open Exam App", command=open_exam_app, state=tk.DISABLED)
open_exam_button.pack(pady=10)

end_button = tk.Button(root, text="End Exam", command=end_exam)
end_button.pack(pady=20)

# ✅ Bind Close Event
root.protocol("WM_DELETE_WINDOW", on_close)

# ✅ Main GUI Loop
root.mainloop()