import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import threading
import time
import queue
from risk_score import risk_queue, warning_queue
import main  # Ensure main.py functions can be accessed
import queue

# Global Variables
exam_started = False
timer_label = None
exam_duration = 3600  # 1 hour

def update_risk_label():
    """Update the risk score label in real time."""
    try:
        while True:
            new_risk_score = risk_queue.get_nowait()
            risk_label.config(text=f"Risk Score: {new_risk_score}")

            # Display warning at high risk
            if new_risk_score >= 50:
                messagebox.showwarning("⚠️ High Risk!", "Your risk score is high! Further suspicious activity may result in exam termination.")

            # Automatically terminate exam at risk 80+
            if new_risk_score >= 80:
                messagebox.showerror("🚨 Exam Terminated!", "Suspicious activity detected. Your exam has been terminated.")
                end_exam()
                return

    except queue.Empty:
        pass
    root.after(1000, update_risk_label)  # Refresh every second

# Setup main application window
if getattr(sys, 'frozen', False):
    bundle_dir = sys._MEIPASS
else:
    bundle_dir = os.path.dirname(os.path.abspath(__file__))

sys.path.append(bundle_dir)

root = tk.Tk()
root.title("Student Proctoring System")
root.geometry("600x500")
root.resizable(False, False)

# Use ttk styles for a modern look
style = ttk.Style(root)
style.theme_use("clam")
style.configure("TFrame", background="#f0f0f0")
style.configure("TLabel", background="#f0f0f0", font=("Helvetica", 12))
style.configure("Header.TLabel", font=("Helvetica", 16, "bold"))
style.configure("TButton", font=("Helvetica", 12))
style.configure("TEntry", font=("Helvetica", 12))

# Main Frame
main_frame = ttk.Frame(root, padding=20)
main_frame.pack(expand=True, fill="both")

# Header Label
header_label = ttk.Label(main_frame, text="Student Proctoring System", style="Header.TLabel")
header_label.pack(pady=(0, 20))

# Risk Score Label
risk_label = ttk.Label(main_frame, text="Risk Score: 0", foreground="red", font=("Helvetica", 14))
risk_label.pack(pady=(0, 20))

# User Info Frame (Single Set of Username/Exam Code)
user_frame = ttk.Frame(main_frame)
user_frame.pack(pady=10, fill="x", expand=True)

ttk.Label(user_frame, text="Username:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
username_entry = ttk.Entry(user_frame, width=30)
username_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)

ttk.Label(user_frame, text="Exam Code:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
exam_code_entry = ttk.Entry(user_frame, width=30)
exam_code_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=5)

user_frame.columnconfigure(1, weight=1)

# Buttons Frame
button_frame = ttk.Frame(main_frame)
button_frame.pack(pady=20)

start_button = ttk.Button(button_frame, text="Start Exam", command=lambda: show_consent_form())
start_button.grid(row=0, column=0, padx=10)

open_exam_button = ttk.Button(button_frame, text="Open Exam App", command=lambda: open_exam_app(), state=tk.DISABLED)
open_exam_button.grid(row=0, column=1, padx=10)

end_button = ttk.Button(button_frame, text="End Exam", command=lambda: end_exam())
end_button.grid(row=0, column=2, padx=10)

# Timer Label
timer_label = ttk.Label(main_frame, text="Time Remaining: 01:00:00", font=("Helvetica", 14))
timer_label.pack(pady=20)

def show_consent_form():
    """Display a consent form with terms and a checkbox to agree."""
    consent_win = tk.Toplevel(root)
    consent_win.title("Consent Form")
    consent_win.resizable(False, False)
    consent_win.grab_set()  # Make it modal (can't click the main window behind it)

    # Frame for the content
    frame = ttk.Frame(consent_win, padding=20)
    frame.pack(expand=True, fill="both")

    # Example Terms & Conditions
    terms = (
        "By proceeding, you agree to the following terms and conditions:\n\n"
        "1. Your activity will be monitored during the exam.\n"
        "2. Unauthorized applications may be terminated.\n"
        "3. Your exam session may be terminated if suspicious activity is detected.\n\n"
        "Please confirm your consent to continue."
    )

    # Label with wrapped text so it doesn't force the window too wide
    terms_label = ttk.Label(frame, text=terms, wraplength=350, justify="left")
    terms_label.pack(pady=(0, 10))

    # A standard tk.Checkbutton with a check mark
    consent_var = tk.BooleanVar(value=False)
    consent_check = tk.Checkbutton(
        frame,
        text="I agree to the terms and conditions",
        variable=consent_var,
        onvalue=True,
        offvalue=False
    )
    consent_check.pack(pady=10)

    # Buttons Frame
    btn_frame = ttk.Frame(frame)
    btn_frame.pack(pady=10)

    def consent_ok():
        if consent_var.get():
            consent_win.destroy()
            start_exam_action()  # Proceed to start the exam
        else:
            messagebox.showwarning("Consent Required", "You must agree to the terms and conditions to proceed.")

    ok_btn = ttk.Button(btn_frame, text="I Agree", command=consent_ok)
    ok_btn.grid(row=0, column=0, padx=5)

    cancel_btn = ttk.Button(btn_frame, text="Cancel", command=consent_win.destroy)
    cancel_btn.grid(row=0, column=1, padx=5)

    # Let the window size itself, then center it on the screen
    consent_win.withdraw()
    consent_win.update_idletasks()  # Calculate required size
    width = consent_win.winfo_reqwidth()
    height = consent_win.winfo_reqheight()
    x = (consent_win.winfo_screenwidth() // 2) - (width // 2)
    y = (consent_win.winfo_screenheight() // 2) - (height // 2)
    consent_win.geometry(f"{width}x{height}+{x}+{y}")
    consent_win.deiconify()

def open_exam_app():
    """Open whitelisted applications."""
    exam_apps = main.WHITELISTED_PROCESSES

    if not exam_apps:
        messagebox.showerror("Error", "No whitelisted exam apps are configured. Please contact the admin.")
        return

    failed_apps, opened_apps = [], []
    system_processes = ["explorer.exe", "winlogon.exe", "csrss.exe", "services.exe", 
                        "svchost.exe", "lsass.exe", "dwm.exe", "system", "smss.exe"]

    for app in exam_apps:
        if app.lower() in system_processes:
            continue  # Skip system processes

        try:
            subprocess.Popen([app], shell=True)
            opened_apps.append(app)
        except Exception as e:
            failed_apps.append(f"{app} ({str(e)})")

    if opened_apps:
        messagebox.showinfo("Exam Apps Opened", f"The following exam apps have been opened: {', '.join(opened_apps)}")

    if failed_apps:
        messagebox.showerror("Error", f"The following exam apps could not be opened: {', '.join(failed_apps)}. Please contact the admin.")

def start_exam_action():
    """Start the exam, risk monitoring, and timer (actual action after consent)."""
    global exam_started

    username = username_entry.get().strip()
    exam_code = exam_code_entry.get().strip()

    if not username or not exam_code:
        messagebox.showerror("Error", "Please enter username and exam code!")
        return

    # Add the app itself to the whitelist to prevent self-termination
    exe_name = os.path.basename(sys.executable).lower()  # Convert to lowercase
    if exe_name not in [p.lower() for p in main.WHITELISTED_PROCESSES]:
        main.WHITELISTED_PROCESSES.append(exe_name)

    messagebox.showinfo("Whitelisted Processes", "The necessary processes have been whitelisted.")

    exam_started = True
    messagebox.showinfo("Exam Started", f"The exam has started. Good luck, {username}!")

    # Enable "Open Exam App" button
    open_exam_button.config(state=tk.NORMAL)

    # Start monitoring threads
    threading.Thread(target=main.start_monitoring, daemon=True).start()
    threading.Thread(target=main.monitor_network, daemon=True).start()
    threading.Thread(target=update_risk_label, daemon=True).start()

    # Start countdown timer
    timer_label.config(text="Time Remaining: 01:00:00")
    start_timer(exam_duration)

def start_timer(duration):
    """Start the countdown timer."""
    def update_timer(remaining):
        if remaining > 0 and exam_started:
            mins, secs = divmod(remaining, 60)
            timer_label.config(text=f"Time Remaining: {mins:02}:{secs:02}")
            root.after(1000, update_timer, remaining - 1)
        elif exam_started:
            timer_label.config(text="Time's up!")
            messagebox.showinfo("Time's Up", "The exam time has ended.")
            end_exam()

    update_timer(duration)

def end_exam():
    """End the exam session."""
    global exam_started
    if not exam_started:
        messagebox.showerror("Error", "No exam is currently running.")
        return

    confirm = messagebox.askyesno("End Exam", "Are you sure you want to end the exam?")
    if confirm:
        exam_started = False
        messagebox.showinfo("Exam Ended", "The exam has ended. Thank you for your participation.")
        root.quit()

def on_close():
    """Confirm before closing the exam window."""
    if exam_started:
        confirm = messagebox.askyesno("Warning", "Closing this window will end the exam immediately. Are you sure?")
        if confirm:
            root.destroy()
    else:
        root.destroy()

root.protocol("WM_DELETE_WINDOW", on_close)

if __name__ == "__main__":
    root.mainloop()
