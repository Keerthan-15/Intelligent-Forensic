import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from models import SessionLocal, SystemLog
from forensics import hash_evidence
import datetime
import os

class FileMonitorHandler(FileSystemEventHandler):
    def log_event(self, event_type, filepath):
        if filepath.endswith('.tmp') or '~' in filepath:
            return # Ignore temporary files to avoid noise
            
        db = SessionLocal()
        try:
            # Simple heuristic
            risk_score = 0.0
            # High risk if system files or rapid changes
            if filepath.endswith(('.exe', '.dll', '.sys')):
                risk_score = 60.0
                
            event_data = {
                'timestamp': datetime.datetime.now(),
                'event_type': 'FILE',
                'description': f"File {event_type}: {os.path.basename(filepath)}",
                'source': filepath,
                'risk_score': risk_score,
                'is_anomaly': risk_score > 50.0
            }
            
            hash_val = hash_evidence(event_data)
            
            log_entry = SystemLog(
                timestamp=event_data['timestamp'],
                event_type=event_data['event_type'],
                description=event_data['description'],
                source=event_data['source'],
                risk_score=event_data['risk_score'],
                is_anomaly=event_data['is_anomaly'],
                hash_value=hash_val
            )
            
            db.add(log_entry)
            db.commit()
            print(f"[FILE] Logged {event_type}: {os.path.basename(filepath)}")
        except Exception as e:
            print(f"Error logging file event: {e}")
            db.rollback()
        finally:
            db.close()

    def on_created(self, event):
        if not event.is_directory:
            self.log_event('created', event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.log_event('modified', event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.log_event('deleted', event.src_path)

class FileMonitor:
    def __init__(self, path_to_watch):
        self.path_to_watch = path_to_watch
        self.observer = Observer()
        self.handler = FileMonitorHandler()

    def start(self):
        self.observer.schedule(self.handler, self.path_to_watch, recursive=True)
        self.observer.start()

    def stop(self):
        self.observer.stop()
        self.observer.join()

if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else '.'
    monitor = FileMonitor(path)
    monitor.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()
