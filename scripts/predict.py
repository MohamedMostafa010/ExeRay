# malware_detector/scripts/predict.py
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
    
    # Create DataFrame with same column order as training data
    df = pd.DataFrame([features])
    
    try:
        proba = model.predict_proba(df)[0][1]
        
        # Use provided threshold or optimal threshold
        decision_threshold = threshold if threshold is not None else optimal_threshold
        
        result = {
            "status": "success",
            "filename": os.path.basename(filepath),
            "prediction": "MALWARE" if proba > decision_threshold else "BENIGN",
            "malware_probability": float(proba),
            "confidence_level": interpret_confidence(proba),
            "decision_threshold": float(decision_threshold),
            "features": features  # Include all extracted features
        }
        return result
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
        
        # Define suspicious features to check
        SUSPICIOUS_FEATURES = {
            # Packing and obfuscation
            'has_packed_sections': "Packed sections detected",
            'section_names_entropy': "High section name entropy",
            'avg_entropy': "High average section entropy",
            'max_entropy': "High maximum section entropy",
            
            # Anti-analysis
            'has_anti_debug': "Anti-debugging strings detected",
            'has_anti_debug_imports': "Anti-debugging API imports",
            'has_anti_debug_strings': "Anti-debugging strings in code",
            'has_vm_detection_imports': "VM detection API imports",
            'has_vm_detection_strings': "VM detection strings in code",
            'has_vm_mac_addresses': "VM MAC addresses in strings",
            
            # Suspicious imports
            'has_import_name_mismatches': "Import name mismatches",
            'suspicious_imports_count': "Suspicious API imports",
            'suspicious_api_chains': "Suspicious API call chains",
            'has_process_creation_imports': "Process creation APIs",
            'has_createprocess': "CreateProcess API found",
            'has_setwindowshookex': "SetWindowsHookEx API found",
            
            # Code patterns
            'has_nop_sleds': "NOP sleds detected",
            
            # Structural anomalies
            'has_suspicious_sections': "Suspicious section names",
            'has_tls': "Thread Local Storage detected",
            'has_embedded_exe': "Embedded executable in resources",
            'writable_executable_sections': "Writable and executable sections",
            
            # Other indicators
            'is_signed': "Digital signature status",
            'has_rich_header': "Rich header present",
            'suspicious_exports': "Suspicious export functions"
        }

        # Show top suspicious features if malware
        if result.get('prediction') == "MALWARE" and 'features' in result:
            print("\nTop Suspicious Features:")
            suspicious_features = []
            for k, v in result['features'].items():
                try:
                    if k in SUSPICIOUS_FEATURES:
                        if (isinstance(v, bool) and v) or (isinstance(v, (int, float)) and v > 0):
                            suspicious_features.append((SUSPICIOUS_FEATURES[k], v))
                except KeyError:
                    continue  # Skip features not in our suspicious features list
            
            # Sort by most suspicious (highest values first)
            suspicious_features.sort(key=lambda x: abs(x[1]) if isinstance(x[1], (int, float)) else 0, reverse=True)
            
            for desc, val in suspicious_features[:10]:  # Show top 10 most suspicious
                if isinstance(val, bool):
                    print(f"- {desc}")
                elif isinstance(val, int):
                    print(f"- {desc}: {val}")
                else:  # float values
                    print(f"- {desc}: {val:.3f}")  # Format to 3 decimal places
    else:
        print("Usage: python predict.py <path_to_exe>")
