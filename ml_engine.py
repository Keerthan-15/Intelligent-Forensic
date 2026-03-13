import pandas as pd
from sklearn.ensemble import IsolationForest
import pickle
import os

class ForensicsMLEngine:
    def __init__(self, model_path='data/iso_forest_model.pkl'):
        self.model_path = model_path
        self.model = None
        self.is_trained = False
        self.load_model()
        
    def load_model(self):
        if os.path.exists(self.model_path):
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
            self.is_trained = True
            
    def train_model(self, dataset_path='data/training_data.csv'):
        if not os.path.exists(dataset_path):
            print(f"Dataset {dataset_path} not found.")
            return False
            
        df = pd.read_csv(dataset_path)
        # Drop the label for unsupervised training, but we keep it in CSV for reference/evaluation
        X = df[['event_type_encoded', 'hour_of_day', 'frequency_score', 'path_risk_score']]
        
        # Isolation Forest is an unsupervised anomaly detection algorithm
        # contamination sets the expected proportion of outliers
        self.model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        self.model.fit(X)
        
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)
            
        self.is_trained = True
        print(f"Model trained and saved to {self.model_path}")
        return True

    def predict(self, features):
        """
        Takes in a dictionary or feature array and returns if it's an anomaly.
        Return: (is_anomaly, score) 
        where is_anomaly is boolean, and score is anomaly score (lower is more anomalous in sklearn isolation forest).
        We transform the score to a risk score from 0-100 where higher is more risk.
        """
        if not self.is_trained:
            return False, 0.0
            
        # Example features: [event_type_encoded, hour_of_day, frequency_score, path_risk_score]
        # map event_type string to 0,1,2,3
        event_mapping = {'PROCESS': 0, 'FILE': 1, 'AUTH': 2, 'USB': 3}
        event_code = event_mapping.get(features.get('event_type'), 0)
        hour = features.get('hour', 12)
        freq = features.get('frequency_score', 0.2)
        path_risk = features.get('path_risk', 0.1)
        
        X = [[event_code, hour, freq, path_risk]]
        
        pred = self.model.predict(X)[0] # 1 for inlier, -1 for outlier
        score = self.model.decision_function(X)[0] # Negative scores are anomalies
        
        is_anomaly = pred == -1
        # Convert score to an intuitive risk score (0-100)
        # Isolation Forest decision_function ranges typically around -0.5 to 0.5. 
        # So we normalize somewhat heuristically for presentation.
        normalized_risk = max(0, min(100, 50 - (score * 100)))
        
        return is_anomaly, normalized_risk

if __name__ == "__main__":
    engine = ForensicsMLEngine()
    engine.train_model()
    
    # Test Normal
    norm_res = engine.predict({'event_type': 'PROCESS', 'hour': 12, 'frequency_score': 0.2, 'path_risk': 0.1})
    print(f"Normal prediction: Anomaly? {norm_res[0]}, Risk: {norm_res[1]}")
    
    # Test Anomaly
    anom_res = engine.predict({'event_type': 'FILE', 'hour': 2, 'frequency_score': 0.9, 'path_risk': 0.8})
    print(f"Anomaly prediction: Anomaly? {anom_res[0]}, Risk: {anom_res[1]}")
