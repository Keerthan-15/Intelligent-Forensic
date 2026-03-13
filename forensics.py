import hashlib
import json
from models import SessionLocal, SystemLog

def hash_evidence(event_data):
    """
    Generates a SHA-256 hash for a structured log entry to ensure data integrity.
    event_data: dictionary containing event details (without the hash field itself)
    """
    # Sort keys to ensure consistent hashing
    event_string = json.dumps(event_data, sort_keys=True, default=str)
    return hashlib.sha256(event_string.encode('utf-8')).hexdigest()

def verify_evidence(log_id):
    """
    Recalculates the hash for a stored log and verifies it matches the stored hash value.
    Returns True if intact, False if tampered or not found.
    """
    db = SessionLocal()
    try:
        log_entry = db.query(SystemLog).filter(SystemLog.id == log_id).first()
        if not log_entry:
            return False
        
        # Reconstruct the dictionary used for hashing
        event_data = {
            'timestamp': log_entry.timestamp,
            'event_type': log_entry.event_type,
            'description': log_entry.description,
            'source': log_entry.source,
            'risk_score': log_entry.risk_score,
            'is_anomaly': log_entry.is_anomaly
        }
        recalculated_hash = hash_evidence(event_data)
        
        return recalculated_hash == log_entry.hash_value
    finally:
        db.close()

def reconstruct_timeline(event_type=None, only_anomalies=False, limit=100):
    """
    Reconstructs the chronological timeline of events.
    Optionally filter by event type or only anomalies.
    """
    db = SessionLocal()
    try:
        query = db.query(SystemLog)
        
        if event_type:
            query = query.filter(SystemLog.event_type == event_type)
        if only_anomalies:
            query = query.filter(SystemLog.is_anomaly == True)
            
        logs = query.order_by(SystemLog.timestamp.desc()).limit(limit).all()
        return [log.to_dict() for log in logs]
    finally:
        db.close()

if __name__ == "__main__":
    # Test hashing
    test_data = {
        'timestamp': '2023-10-27T10:00:00',
        'event_type': 'TEST',
        'description': 'Test description',
        'source': 'Test source',
        'risk_score': 0.0,
        'is_anomaly': False
    }
    print(f"Test hash: {hash_evidence(test_data)}")
