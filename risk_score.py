import queue
import time
import threading

# ✅ Queues for risk score updates & warnings
risk_queue = queue.Queue()
warning_queue = queue.Queue()

# ✅ Risk Score Variable
risk_score = 0
event_buffer = []  # ✅ Initialize event buffer globally
event_counts = {}  # ✅ Dictionary to count occurrences of each event type


# ✅ Define sequence patterns and risk levels
sequence_patterns = {
    "basic": [
        ["Tab Switch", "Clipboard Paste"],
        ["Window Switch", "Clipboard Paste"]
    ],
    "medium": [
        ["Tab Switch", "Clipboard Paste", "Typing Speed Spike"],
        ["Window Switch", "Process Monitoring Alert", "Clipboard Paste"]
    ],
    "high": [
        ["Tab Switch", "Clipboard Paste", "Network Request", "Typing Speed Spike"]
    ],
    "critical": [
        ["Tab Switch", "Clipboard Paste", "AI Tool Detected", "Network Request", "Keystroke Anomaly"]
    ]
}

# ✅ Base risk scores for patterns
base_risk_scores = {
    "basic": 2,
    "medium": 8,
    "high": 20,
    "critical": 45
}

# ✅ Function to check if recent events match a pattern
def buffer_ends_with_pattern(buffer, pattern):
    if len(buffer) < len(pattern):
        return False
    return buffer[-len(pattern):] == pattern

# ✅ Function to update event counts
def update_event_counts(event_type):
    event_counts[event_type] = event_counts.get(event_type, 0) + 1
    return event_counts[event_type]

# ✅ Function to calculate a weighted multiplier
def weighted_multiplier(pattern):
    total = sum(event_counts.get(event, 0) for event in pattern)
    return total / len(pattern) if pattern else 1

# ✅ Risk Score Calculation

def calculate_risk(event_stream):
    """Calculate and update risk score based on detected events."""
    global risk_score, event_buffer  # ✅ Ensure global variables are used

    while True:
        try:
            event_type = event_stream.get(timeout=1)  # ⏳ Wait for new event
        except queue.Empty:
            continue  # Keep waiting if no event

        # ✅ Ensure event_buffer exists before appending
        if event_type:
            event_buffer.append(event_type)  # Now event_buffer is properly initialized
            update_event_counts(event_type)

        # ✅ Check for matching suspicious sequences
        for seq_type, patterns in sequence_patterns.items():
            for pattern in patterns:
                if buffer_ends_with_pattern(event_buffer, pattern):
                    multiplier = weighted_multiplier(pattern)
                    risk_score += base_risk_scores[seq_type] * multiplier
                    event_buffer = event_buffer[-10:]  # Keep buffer size manageable

        # ✅ Cap risk score at 100
        risk_score = min(risk_score, 100)
        risk_queue.put(risk_score)  # 🔄 Update GUI risk score in real time

        # ✅ Trigger warnings at high risk
        if risk_score >= 50:
            warning_queue.put("⚠️ High Risk! Further cheating attempts may terminate your exam.")
        if risk_score >= 80:
            warning_queue.put("🚨 Exam Terminated due to excessive cheating attempts!")
            break  # Stop monitoring

        time.sleep(0.5)  # Update risk score every 0.5 sec
        
# ✅ Start Risk Monitoring in a Thread
def start_risk_monitoring(event_stream):
    risk_thread = threading.Thread(target=calculate_risk, args=(event_stream,), daemon=True)
    risk_thread.start()
