from flask import Flask, render_template, jsonify
from forensics import reconstruct_timeline, verify_evidence
from models import SessionLocal, SystemLog, init_db

init_db()

app = Flask(__name__)
from models import Base, engine
Base.metadata.create_all(bind=engine) 

def get_stats():
    db = SessionLocal()
    stats = {}
    try:
        stats['total_events'] = db.query(SystemLog).count()
        stats['total_anomalies'] = db.query(SystemLog).filter(SystemLog.is_anomaly == True).count()
        
        # Count by type
        stats['process_cnt'] = db.query(SystemLog).filter(SystemLog.event_type == 'PROCESS').count()
        stats['file_cnt'] = db.query(SystemLog).filter(SystemLog.event_type == 'FILE').count()
        stats['auth_cnt'] = db.query(SystemLog).filter(SystemLog.event_type == 'AUTH').count()
        stats['usb_cnt'] = db.query(SystemLog).filter(SystemLog.event_type == 'USB').count()
    finally:
        db.close()
    return stats

@app.route('/')
def dashboard():
    stats = get_stats()
    return render_template('index.html', stats=stats)

@app.route('/events')
def events():
    db = SessionLocal()
    try:
        events = db.query(SystemLog).order_by(SystemLog.timestamp.desc()).limit(100).all()
        # Ensure we don't pass SQL metrics by converting to dict explicitly or let template access them
        events_list = [v.to_dict() for v in events]
    finally:
        db.close()
    return render_template('events.html', events=events_list)

@app.route('/anomalies')
def anomalies():
    db = SessionLocal()
    try:
        events = db.query(SystemLog).filter(SystemLog.is_anomaly == True).order_by(SystemLog.risk_score.desc()).limit(50).all()
        events_list = [v.to_dict() for v in events]
    finally:
        db.close()
    return render_template('anomalies.html', events=events_list)

@app.route('/timeline')
def timeline():
    timeline_events = reconstruct_timeline(limit=50)
    return render_template('timeline.html', events=timeline_events)

@app.route('/api/verify/<int:log_id>', methods=['POST'])
def verify_hash(log_id):
    is_valid = verify_evidence(log_id)
    return jsonify({'id': log_id, 'verified': is_valid})

@app.route('/api/stats')
def api_stats():
    # Helper API for ajax chart updates
    stats = get_stats()
    return jsonify(stats)

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
