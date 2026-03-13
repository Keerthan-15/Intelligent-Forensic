import pandas as pd
import numpy as np
import random
import os

def generate_dataset(num_samples=5000):
    np.random.seed(42)
    random.seed(42)
    
    data = []
    for _ in range(num_samples):
        # Normal behavior is much more frequent than anomalous behavior
        is_anomaly = random.random() < 0.05
        
        if not is_anomaly:
            # Normal: low CPU/Memory heuristics, normal file paths, successful logins
            event_type = random.choice([0, 1, 2, 3]) # 0: PROCESS, 1: FILE, 2: AUTH, 3: USB
            hour_of_day = random.randint(8, 18) # Business hours
            frequency_score = random.uniform(0.1, 0.4)
            path_risk_score = random.uniform(0.0, 0.2)
        else:
            # Anomaly: odd hours, high risk paths, rapid frequency
            event_type = random.choice([0, 1, 2, 3])
            hour_of_day = random.choice([random.randint(0, 7), random.randint(19, 23)]) # Off-hours
            frequency_score = random.uniform(0.7, 1.0) # Rapidly repeating events (e.g. brute force, ransomware)
            path_risk_score = random.uniform(0.6, 1.0) # E.g. temp dirs, system32 changes
            
        data.append([event_type, hour_of_day, frequency_score, path_risk_score, 1 if is_anomaly else 0])
        
    df = pd.DataFrame(data, columns=['event_type_encoded', 'hour_of_day', 'frequency_score', 'path_risk_score', 'label'])
    
    os.makedirs('data', exist_ok=True)
    df.to_csv('data/training_data.csv', index=False)
    print(f"Dataset generated at data/training_data.csv with {num_samples} records.")
    
if __name__ == "__main__":
    generate_dataset()
