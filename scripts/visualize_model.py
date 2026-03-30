import joblib
import pandas as pd
import xgboost as xgb
import matplotlib.pyplot as plt
import numpy as np

# Paths
MODEL_PATH = r"" # Model Path Here
DATASET_PATH = r"" # Dataset Path Here

# Load model with version compatibility info
print("=" * 60)
print("Malware Detector Model Analysis")
print("=" * 60)

model = joblib.load(MODEL_PATH)

# Extract XGBoost model
if hasattr(model, 'calibrated_classifiers_'):
    xgb_model = model.calibrated_classifiers_[0].estimator
    print(f"Model type: Calibrated XGBoost (scikit-learn calibration wrapper)")
elif hasattr(model, 'base_estimator'):
    xgb_model = model.base_estimator
    print(f"Model type: XGBoost with wrapper")
else:
    xgb_model = model
    print(f"Model type: Pure XGBoost")

# Model statistics
print(f"\n--- Model Architecture ---")
print(f"Number of trees (estimators): {xgb_model.n_estimators}")
print(f"Max tree depth: {xgb_model.max_depth}")
print(f"Learning rate: {xgb_model.learning_rate}")

# Calculate approximate parameters
max_nodes_per_tree = (2 ** xgb_model.max_depth) - 1
approx_splits = xgb_model.n_estimators * max_nodes_per_tree
print(f"Approximate decision nodes: ~{approx_splits}")
print(f"Approximate parameters: ~{approx_splits * 2} (feature + threshold per node)")

# Load features
df = pd.read_csv(DATASET_PATH)
feature_names = df.drop('label', axis=1).columns.tolist()
print(f"\n--- Input Features ---")
print(f"Total features: {len(feature_names)}")
print(f"First 5 features: {feature_names[:5]}")

# Load labels to understand class distribution
if 'label' in df.columns:
    labels = df['label']
    malware_count = (labels == 1).sum() if labels.dtype == 'int' else (labels == 'malware').sum()
    benign_count = len(labels) - malware_count
    print(f"\n--- Dataset Statistics ---")
    print(f"Total samples: {len(df)}")
    print(f"Malware samples: {malware_count} ({malware_count/len(df)*100:.1f}%)")
    print(f"Benign samples: {benign_count} ({benign_count/len(df)*100:.1f}%)")

# Visualize trees (fixed for deprecated warning)
print(f"\n--- Generating Visualizations ---")
tree_indices = [0, 1, 2, xgb_model.n_estimators - 1]  # First, second, third, last

for tree_idx in tree_indices:
    plt.figure(figsize=(25, 15))
    # Fixed: use tree_idx instead of num_trees
    xgb.plot_tree(xgb_model, tree_idx=tree_idx, rankdir='LR')
    plt.title(f'XGBoost Tree #{tree_idx} - Malware Detector\nDepth: {xgb_model.max_depth}')
    plt.savefig(f'xgb_tree_{tree_idx}.png', dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  ✓ Saved: xgb_tree_{tree_idx}.png")

# Feature importance
fig, ax = plt.subplots(figsize=(12, 8))
xgb.plot_importance(xgb_model, max_num_features=20, ax=ax, importance_type='weight')
plt.title('Top 20 Most Important Features for Malware Detection\n(by frequency of use in splits)')
plt.tight_layout()
plt.savefig('feature_importances.png', dpi=150, bbox_inches='tight')
print(f"  ✓ Saved: feature_importances.png")

# Additional: Feature importance by gain (better metric)
fig, ax = plt.subplots(figsize=(12, 8))
xgb.plot_importance(xgb_model, max_num_features=20, ax=ax, importance_type='gain')
plt.title('Top 20 Features by Information Gain\n(how much each feature improves detection)')
plt.tight_layout()
plt.savefig('feature_importances_gain.png', dpi=150, bbox_inches='tight')
print(f"  ✓ Saved: feature_importances_gain.png")

print("\n" + "=" * 60)
print("Analysis Complete! Files generated:")
print("  - xgb_tree_0.png, xgb_tree_1.png, xgb_tree_2.png, xgb_tree_99.png")
print("  - feature_importances.png")
print("  - feature_importances_gain.png")
print("=" * 60)

# Model size analysis
import os
model_size_bytes = os.path.getsize(MODEL_PATH)
print(f"\nModel file size: {model_size_bytes / 1024:.1f} KB")
print(f"This is {model_size_bytes / (175e9) * 100:.10f}% the size of GPT-3!")