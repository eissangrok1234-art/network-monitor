import datetime

LOG_FILE = "logs.txt"

def log_event(message):
    time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(LOG_FILE, "a") as f:
        f.write(f"[{time}] {message}\n")