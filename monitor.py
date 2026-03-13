import threading
import time
from collectors.process_monitor import ProcessMonitor
from collectors.file_monitor import FileMonitor
from collectors.auth_monitor import AuthMonitor
from collectors.usb_monitor import USBMonitor
from models import init_db
import os

def run_process_monitor():
    print("Starting Process Monitor...")
    pm = ProcessMonitor()
    while True:
        pm.monitor()
        time.sleep(2)

def run_file_monitor():
    watch_path = os.path.expanduser('~') # Watch User Directory
    print(f"Starting File Monitor on {watch_path}...")
    fm = FileMonitor(watch_path)
    fm.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        fm.stop()

def run_auth_monitor():
    print("Starting Auth Monitor...")
    am = AuthMonitor()
    while True:
        am.check_auth_events()
        time.sleep(3)

def run_usb_monitor():
    print("Starting USB Monitor...")
    um = USBMonitor()
    while True:
        um.check_usb_events()
        time.sleep(5)

if __name__ == "__main__":
    print('Initializing Database...')
    init_db()
    
    threads = [
        threading.Thread(target=run_process_monitor, daemon=True),
        # threading.Thread(target=run_file_monitor, daemon=True), # Can be heavy, disabled by default for test
        threading.Thread(target=run_auth_monitor, daemon=True),
        threading.Thread(target=run_usb_monitor, daemon=True)
    ]
    
    for t in threads:
        t.start()
        
    print("Intelligent Forensics Monitor is now active. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down monitor...")
