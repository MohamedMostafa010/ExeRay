import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold
from sklearn.metrics import classification_report, roc_auc_score, roc_curve
from sklearn.calibration import CalibratedClassifierCV
from xgboost import XGBClassifier
from imblearn.under_sampling import RandomUnderSampler
from tqdm import tqdm

DATASET_PATH = "../output/malware_dataset.csv"
MODEL_PATH = "../models/malware_detector.joblib"
THRESHOLD_PATH = "../models/optimal_threshold.npy"

def load_and_preprocess_data():
    """Load and preprocess the dataset."""
    df = pd.read_csv(DATASET_PATH)
    
    # Handle missing values
    df.fillna(df.median(numeric_only=True), inplace=True) # replaces NaN values. df.median(numeric_only=True): calculates the median only for numeric columns.
    
    # Separate features and target
    X = df.drop("label", axis=1)
    y = df["label"]
    
    return X, y

def find_optimal_threshold(model, X_test, y_test):
    y_scores = model.predict_proba(X_test)[:, 1]
    fpr, tpr, thresholds = roc_curve(y_test, y_scores)
    optimal_idx = np.argmax(tpr - fpr)
    return thresholds[optimal_idx]

def train():
    X, y = load_and_preprocess_data()
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Balance the training set
    rus = RandomUnderSampler(random_state=42) # It's a fixed starting point for a random number generator. It makes the "random" process predictable and reproducible.
    X_train_res, y_train_res = rus.fit_resample(X_train, y_train) # X_train = Your training features (like size, entropy, etc.), y_train = Your training labels (0 = benign, 1 = malicious)
    
    models = {
        'XGBoost': {
            'model': XGBClassifier(random_state=42, eval_metric='logloss'),
            'params': { # Parameters (or hyperparameters) are settings you choose before training the model. They affect how the model learns.
                'n_estimators': [100, 200], # This means: try using 100 trees and 200 trees, and see which gives better results.
                'max_depth': [3, 6, 9], # This is how deep each decision tree can go. Deeper trees can learn more complex things, but might overfit.
                'learning_rate': [0.01, 0.1] # This controls how fast the model learns. A smaller value = more careful learning.
            }
        },
        'RandomForest': {
            'model': RandomForestClassifier(random_state=42),
            'params': { # Parameters (or hyperparameters) are settings you choose before training the model. They affect how the model learns.
                'n_estimators': [100, 200], # This means: try using 100 trees and 200 trees, and see which gives better results.
                'max_depth': [None, 10, 20], # This is how deep each decision tree can go. Deeper trees can learn more complex things, but might overfit.
                'min_samples_split': [2, 5] # This controls how fast the model learns. A smaller value = more careful learning.
            }
        }
    }
    
    best_score = 0
    best_model = None
    
    for name, config in tqdm(models.items(), desc="Training models"):
        grid_search = GridSearchCV( # Think of GridSearchCV like a robot chef tester: You give it a model (like XGBoost or RandomForest).
            config['model'], # This is the actual model (like XGBClassifier() or RandomForestClassifier())
            config['params'], # A dictionary of all the different settings (parameters) we want to try, like number of trees or depth
            cv=StratifiedKFold(n_splits=5), # Cross-validation: the data is split into 5 parts, and each part gets a turn being tested — this avoids overfitting
            scoring='f1', # Tells it to choose the best model based on the F1 score, which balances precision and recall
            n_jobs=-1 # Use all CPU cores — speeds things up a lot
        )
        grid_search.fit(X_train_res, y_train_res)
        
        if grid_search.best_score_ > best_score:
            best_score = grid_search.best_score_
            best_model = grid_search.best_estimator_
            print(f"\nNew best model: {name} with F1={best_score:.3f}")
    
    # Calibrate the best model
    calibrated_model = CalibratedClassifierCV(
        best_model, method='sigmoid', cv=5
    )
    calibrated_model.fit(X_train_res, y_train_res) # We now retrain the model + calibration on the training data.
    
    # Evaluation
    y_pred = calibrated_model.predict(X_test)
    y_proba = calibrated_model.predict_proba(X_test)[:, 1]
    
    print("\n=== Final Evaluation ===") # After training and calibrating the model, it tests it on unseen data (the 20% test set):
    print(classification_report(y_test, y_pred))
    print(f"ROC AUC Score: {roc_auc_score(y_test, y_proba):.3f}")
    
    # Find and save optimal threshold
    optimal_threshold = find_optimal_threshold(calibrated_model, X_test, y_test)
    np.save(THRESHOLD_PATH, optimal_threshold)
    print(f"\nOptimal threshold: {optimal_threshold:.3f}")
    
    # Save the model
    joblib.dump(calibrated_model, MODEL_PATH)
    print(f"\nModel saved to {MODEL_PATH}")

if __name__ == "__main__":
    train()

