import psutil
import time
from models import SessionLocal, SystemLog
from forensics import hash_evidence
import datetime

class ProcessMonitor:
    def __init__(self):
        self.known_processes = set()
        self._init_known_processes()

    def _init_known_processes(self):
        for proc in psutil.process_iter(['pid']):
            self.known_processes.add(proc.info['pid'])

    def log_process(self, proc):
        db = SessionLocal()
        try:
            name = proc.info.get('name', 'Unknown')
            exe = proc.info.get('exe', 'Unknown')
            pid = proc.info.get('pid')
            
            # Simple risk heuristic: processes running from temp or suspicious locations
            risk_score = 0.0
            if exe and ('temp' in exe.lower() or 'appdata' in exe.lower()):
                risk_score = 50.0
                
            event_data = {
                'timestamp': datetime.datetime.now(),
                'event_type': 'PROCESS',
                'description': f"New process started: {name} (PID: {pid})",
                'source': exe if exe else str(name),
                'risk_score': risk_score,
                'is_anomaly': risk_score > 40.0
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
            print(f"[PROCESS] Logged: {name}")
        except psutil.NoSuchProcess:
            pass # Process ended before we could log it
        except Exception as e:
            print(f"Error logging process: {e}")
            db.rollback()
        finally:
            db.close()

    def monitor(self):
        try:
            current_processes = set()
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                pid = proc.info['pid']
                current_processes.add(pid)
                
                if pid not in self.known_processes:
                    self.log_process(proc)
                    
            self.known_processes = current_processes
        except Exception as e:
            print(f"Error in process monitor: {e}")

if __name__ == "__main__":
    pm = ProcessMonitor()
    while True:
        pm.monitor()
        time.sleep(2)
