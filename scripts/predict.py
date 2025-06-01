import joblib
import pandas as pd
import numpy as np
import os
from typing import Dict, Optional
from extract_features import extract_features

MODEL_PATH = "../models/malware_detector.joblib"
THRESHOLD_PATH = "../models/optimal_threshold.npy"

try:
    model = joblib.load(MODEL_PATH)
    optimal_threshold = np.load(THRESHOLD_PATH).item()
except Exception as e:
    raise RuntimeError(f"Failed to load model: {str(e)}")

def interpret_confidence(probability: float) -> str:
    if probability < 0.2:
        return "VERY_LOW"
    elif probability < 0.4:
        return "LOW"
    elif probability < 0.6:
        return "MEDIUM"
    elif probability < 0.8:
        return "HIGH"
    else:
        return "VERY_HIGH"

def predict(filepath: str, threshold: Optional[float] = None) -> Dict:
    if not os.path.isfile(filepath):
        return {"error": f"File not found: {filepath}", "status": "error"}
    
    features = extract_features(filepath)
    if not features:
        return {"error": "Invalid PE file or feature extraction failed", "status": "error"}
    
    df = pd.DataFrame([features])
    
    try:
        proba = model.predict_proba(df)[0][1] # returns probabilities for each class (e.g., benign vs malicious).
        
        # Use provided threshold or optimal threshold
        decision_threshold = threshold if threshold is not None else optimal_threshold
        
        return {
            "status": "success",
            "filename": os.path.basename(filepath),
            "prediction": "MALWARE" if proba > decision_threshold else "BENIGN",
            "malware_probability": float(proba),
            "confidence_level": interpret_confidence(proba),
            "decision_threshold": float(decision_threshold),
            "features": features  # Optional: include extracted features
        }
    except Exception as e:
        return {"error": f"Prediction failed: {str(e)}", "status": "error"}

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        result = predict(sys.argv[1])
        print("\nMalware Detection Results:")
        print("=" * 40)
        print(f"File: {result.get('filename')}")
        print(f"Prediction: {result.get('prediction')}")
        print(f"Malware Probability: {float(result.get('malware_probability', 0)) * 100:.2f}%")
        print(f"Confidence Level: {result.get('confidence_level')}")
        print(f"Decision Threshold: {float(result.get('decision_threshold', 0.5)) * 100:.2f}%")
    else:
        print("Usage: python predict.py <path_to_exe>")

