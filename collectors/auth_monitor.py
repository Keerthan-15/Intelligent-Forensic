import time
import random
from models import SessionLocal, SystemLog
from forensics import hash_evidence
import datetime

class AuthMonitor:
    def __init__(self):
        # In a real system, this would tail /var/log/auth.log or use Windows Event Logs
        # Here we mock it for demonstration
        self.users = ['admin', 'root', 'user1', 'guest']
        self.ips = ['192.168.1.100', '10.0.0.5', '172.16.0.2', '203.0.113.42']

    def check_auth_events(self):
        # MOCK: Randomly generate an auth event
        if random.random() < 0.1: # 10% chance per check
            user = random.choice(self.users)
            ip = random.choice(self.ips)
            success = random.random() > 0.3 # 70% success rate
            
            risk_score = 0.0
            if not success:
                risk_score += 30.0
            if user in ['root', 'admin'] and not success:
                risk_score += 40.0
                
            status = "Successful" if success else "Failed"
            
            self.log_auth(user, ip, status, risk_score)

    def log_auth(self, user, ip, status, risk_score):
        db = SessionLocal()
        try:
            event_data = {
                'timestamp': datetime.datetime.now(),
                'event_type': 'AUTH',
                'description': f"{status} login attempt for user '{user}'",
                'source': ip,
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
            print(f"[AUTH] Logged: {status} login for {user} from {ip}")
        except Exception as e:
            print(f"Error logging auth event: {e}")
            db.rollback()
        finally:
            db.close()

if __name__ == "__main__":
    monitor = AuthMonitor()
    while True:
        monitor.check_auth_events()
        time.sleep(3)
