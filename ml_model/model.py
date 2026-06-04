from pathlib import Path
import joblib
import numpy as np

# Use Path(__file__) so this works regardless of working directory
_BASE = Path(__file__).parent

model = joblib.load(_BASE / "leak_model.pkl")
encoder = joblib.load(_BASE / "label_encoder.pkl")


def predict_leak(pressure: float) -> str:
    """Predict leak status from a pressure reading.

    Returns one of: 'NORMAL', 'WARNING', 'LEAK'
    """
    input_data = np.array([[pressure]])
    prediction = model.predict(input_data)
    result = encoder.inverse_transform(prediction)
    return result[0]
