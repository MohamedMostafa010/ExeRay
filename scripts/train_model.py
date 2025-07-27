# malware_detector/scripts/train_model.py
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold
from sklearn.metrics import classification_report, roc_auc_score, roc_curve, make_scorer, recall_score
from sklearn.calibration import CalibratedClassifierCV
from xgboost import XGBClassifier
from imblearn.under_sampling import RandomUnderSampler
from tqdm import tqdm

DATASET_PATH = "../output/processed_features_dataset.csv"
MODEL_PATH = "../models/malware_detector.joblib"
THRESHOLD_PATH = "../models/optimal_threshold.npy"

def load_and_preprocess_data():
    """Load and preprocess the dataset."""
    df = pd.read_csv(DATASET_PATH) 
    df.fillna(df.median(numeric_only=True), inplace=True) 
    X = df.drop("label", axis=1)
    y = df["label"] 
    return X, y 

def malware_recall_score(y_true, y_pred): 
    """Custom scorer focusing on malware recall."""
    return recall_score(y_true, y_pred, pos_label=1)

def find_optimal_threshold(model, X_test, y_test):
    """Find optimal decision threshold."""
    y_scores = model.predict_proba(X_test)[:, 1]
    fpr, tpr, thresholds = roc_curve(y_test, y_scores)
    return thresholds[np.argmax(tpr - (0.5 * fpr))]

def train():
    X, y = load_and_preprocess_data()
    
    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Balance training data
    rus = RandomUnderSampler(random_state=42) 
    X_train_res, y_train_res = rus.fit_resample(X_train, y_train)
    
    # Model configurations
    models = {
        'XGBoost': {
            'model': XGBClassifier( 
                random_state=42, 
                eval_metric='logloss',
                scale_pos_weight=3,
                early_stopping_rounds=None 
            ),
            'params': {
                'n_estimators': [100], 
                'max_depth': [3, 6], 
                'learning_rate': [0.1] 
            }
        },
        'RandomForest': {
            'model': RandomForestClassifier(
                random_state=42,
                class_weight='balanced'
            ),
            'params': {
                'n_estimators': [100, 200],
                'max_depth': [None, 10],
                'min_samples_split': [2, 5]
            }
        }
    }
    
    # Train models
    best_score = 0
    best_model = None
    scorer = make_scorer(malware_recall_score)
    
    for name, config in tqdm(models.items(), desc="Training models"):
        try:
            grid = GridSearchCV(
                config['model'],
                config['params'],
                cv=StratifiedKFold(n_splits=3),
                scoring=scorer,
                n_jobs=-1
            )
            grid.fit(X_train_res, y_train_res)
            
            if grid.best_score_ > best_score:
                best_score = grid.best_score_
                best_model = grid.best_estimator_
                print(f"\nNew best model: {name} (Recall={best_score:.3f})")
                
        except Exception as e:
            print(f"\n[!] {name} failed: {str(e)}")
            continue
    
    # Calibrate and evaluate
    calibrated = CalibratedClassifierCV(best_model, cv=3, method='sigmoid')
    calibrated.fit(X_train_res, y_train_res)

    # Evaluation metrics
    y_pred = calibrated.predict(X_test) # returns a list of 0s and 1s, one for each test sample.
    y_proba = calibrated.predict_proba(X_test)[:, 1]
    
    print("\n=== Evaluation ===")
    print(classification_report(y_test, y_pred))
    print(f"ROC AUC: {roc_auc_score(y_test, y_proba):.3f}")
    
    # Save artifacts
    np.save(THRESHOLD_PATH, find_optimal_threshold(calibrated, X_test, y_test))
    joblib.dump(calibrated, MODEL_PATH)
    print(f"\nModel saved to {MODEL_PATH}")

if __name__ == "__main__":
    train()
