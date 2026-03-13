import time
import random
from models import SessionLocal, SystemLog
from forensics import hash_evidence
import datetime

class USBMonitor:
    def __init__(self):
        # In a real system, this involves monitoring WMI or udev events
        # Mocked for demo purposes
        self.devices = ['SanDisk_Cruzer_8GB', 'Kingston_DataTraveler', 'WesternDigital_Elements', 'Unknown_Generic_USB']

    def check_usb_events(self):
        if random.random() < 0.05: # 5% chance per check
            device = random.choice(self.devices)
            action = random.choice(['connected', 'disconnected'])
            
            risk_score = 0.0
            if 'Unknown' in device and action == 'connected':
                risk_score = 45.0
                
            self.log_usb(device, action, risk_score)

    def log_usb(self, device, action, risk_score):
        db = SessionLocal()
        try:
            event_data = {
                'timestamp': datetime.datetime.now(),
                'event_type': 'USB',
                'description': f"USB device {action}: {device}",
                'source': device,
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
            print(f"[USB] Logged: Device {device} {action}")
        except Exception as e:
            print(f"Error logging USB event: {e}")
            db.rollback()
        finally:
            db.close()

if __name__ == "__main__":
    monitor = USBMonitor()
    while True:
        monitor.check_usb_events()
        time.sleep(5)
