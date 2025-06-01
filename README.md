# ExeRay :hospital:  
*X-ray Vision for Windows Executables*    

- Detect malicious `.exe` files using machine learning. Extracts **static features (entropy, imports, metadata) and combines ML with heuristic rules for fast, automated classification.**  

---

## :gear: **Features**  
- Hybrid detection **(Random Forest/XGBoost + rule-based checks).**
- **Real-time predictions** with confidence scores.  
- Handles obfuscated/novel malware better than signature-based tools.  

## :wrench: Tech Stack
### **Core Components:**
- **Language:** Python 3.8+
- **ML Frameworks:** scikit-learn, XGBoost
- **PE Analysis:** pefile (for parsing Windows executables)
- **Data Handling:** pandas, numpy
- **Security:** pyzipper (malware sample decryption)
### **Key Workflows:**
- **Feature Extraction:**
  - Static analysis of .exe files (entropy, section headers, imports).
  - Uses pefile to extract metadata and structural features.
- **Model Training:**
  - Hybrid RandomForest + XGBoost ensemble.
  - Threshold calibration for precision/recall balance.

- **Prediction:**
  - Real-time classification with confidence scoring.

## :file_folder: **Directory Structure**  
```plaintext
ExeShield_AI/  
├── data/                # Raw samples  
│   ├── malware/        # Malicious executables  
│   └── benign/        # Clean executables  
├── models/             # Saved models/thresholds  
│   ├── malware_detector.joblib  
│   └── optimal_threshold.npy  
├── output/             # Processed data (CSV/features)
│   └── malware_dataset.csv
├── scripts/            # Core scripts  
│   ├── download_malware_samples.py  
│   ├── extract_features.py  
│   ├── train_model.py  
│   └── predict.py  
└── README.md
```

## :computer: Usage (Commands & Outputs)
### **1. Download Samples**
```bash
> python download_malware_samples.py
API Response Status: ok
Downloading .exe malware: 100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 100/100 [06:07<00:00,  3.67s/it]

? Samples ready!
- Malware samples in: ../data/malware
- Benign samples in:  ../data/benign
```
### **2. Extract Features**
```bash
> python extract_features.py
Dataset saved to ../output/malware_dataset.csv
```
### **3. Train Model**
```bash
> python train_model.py
Training models:   0%|                                                                                                                                                 | 0/2 [00:00<?, ?it/s]
New best model: XGBoost with F1=0.953
Training models:  50%|████████████████████████████████████████████████████████████████████▌                                                                    | 1/2 [00:01<00:01,  1.19s/it]
New best model: RandomForest with F1=0.964
Training models: 100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 2/2 [00:03<00:00,  1.53s/it]

=== Final Evaluation ===
              precision    recall  f1-score   support

           0       0.92      0.96      0.94        24
           1       0.95      0.90      0.93        21

    accuracy                           0.93        45
   macro avg       0.94      0.93      0.93        45
weighted avg       0.93      0.93      0.93        45

ROC AUC Score: 0.951

Optimal threshold: 0.670

Model saved to ../models/malware_detector.joblib
``` 
### **4. Predict Executable**
```bash
> python predict.py "path/to/[benign_file]"
Malware Detection Results:
========================================
File: pestudio.exe
Prediction: BENIGN
Malware Probability: 66.98%
Confidence Level: HIGH
Decision Threshold: 67.05%

> python predict.py "path/to/[suspicious_file]"
Malware Detection Results:
========================================
File: e31b997d118cff687de394cd347248efb5fd0f1d2fa6ba6639c42505c28f4a59.exe
Prediction: MALWARE
Malware Probability: 91.60%
Confidence Level: VERY_HIGH
Decision Threshold: 67.05%
```

## :mag: Handling False Positives
- While ExeShield AI achieves high accuracy, occasional false positives (legitimate files flagged as malware) may occur. Common causes:
  - Legitimate tools with behaviors resembling malware (e.g., putty.exe).
  - Packed/obfuscated benign files (high entropy).
    
**- Example False Positive Output:**
```bash
> python predict.py "C:\Program Files\PuTTY\putty.exe"
Malware Detection Results:
========================================
File: putty.exe
Prediction: MALWARE
Malware Probability: 92.76%
Confidence Level: VERY_HIGH
Decision Threshold: 67.05%
```
### Mitigation Strategies:
- **Adjust Threshold:**
  - Lower the decision threshold in predict.py for stricter filtering
- **Whitelist Trusted Files:**
  - Manually verify and exclude known-safe executables.
- **Retrain the Model:**
  - Add misclassified samples to your dataset and rerun train_model.py.

## 🤝 **Contributing**
- Pull requests are welcome! If you have ideas for new user profiles, simulation modes, or forensic artifacts, feel free to contribute.

## :book: **License**
- This project is released under the **MIT License**.
