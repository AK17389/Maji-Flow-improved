# ============================================
# MAJI-FLOW MACHINE LEARNING TRAINING
# ============================================

import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import LabelEncoder
import joblib

# --------------------------------------------
# LOAD DATASET
# --------------------------------------------
data = pd.read_csv('data/water_pressure.csv')

# --------------------------------------------
# INPUT (PRESSURE)
# --------------------------------------------
X = data[['pressure']]

# --------------------------------------------
# OUTPUT (STATUS)
# --------------------------------------------
y = data['status']

# --------------------------------------------
# CONVERT TEXT LABELS TO NUMBERS
# --------------------------------------------
encoder = LabelEncoder()
y_encoded = encoder.fit_transform(y)

# --------------------------------------------
# CREATE MODEL
# --------------------------------------------
model = DecisionTreeClassifier()

# --------------------------------------------
# TRAIN MODEL
# --------------------------------------------
model.fit(X, y_encoded)

# --------------------------------------------
# SAVE MODEL
# --------------------------------------------
joblib.dump(model, 'ml_model/leak_model.pkl')
joblib.dump(encoder, 'ml_model/label_encoder.pkl')

print("MODEL TRAINED SUCCESSFULLY")