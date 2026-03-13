import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()

class SystemLog(Base):
    __tablename__ = 'system_logs'

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.now, index=True)
    event_type = Column(String(50), index=True) # e.g., 'PROCESS', 'FILE', 'AUTH', 'USB'
    description = Column(String(500))
    source = Column(String(200)) # e.g., process name, file path, IP, USB ID
    
    # ML and Forensics fields
    risk_score = Column(Float, default=0.0)
    is_anomaly = Column(Boolean, default=False)
    hash_value = Column(String(64), unique=True, index=True) # SHA-256 string

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type,
            'description': self.description,
            'source': self.source,
            'risk_score': self.risk_score,
            'is_anomaly': self.is_anomaly,
            'hash_value': self.hash_value
        }

# Database connection setup
# Use SQLite by default for easy setup, but easy to switch to MySQL
DATABASE_URL = "sqlite:///forensics.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)

if __name__ == "__main__":
    init_db()
    print("Database initialized successfully.")
