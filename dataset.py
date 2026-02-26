import pandas as pd
import numpy as np

np.random.seed(42)

# Define the number of samples and features
n_samples = 1000
n_features = 5

# Generate random data for each feature
temperature = np.random.uniform(20, 30, n_samples)
pressure = np.random.uniform(1, 2, n_samples)
vibration = np.random.uniform(0, 1, n_samples)
flow_rate = np.random.uniform(5, 15, n_samples)
power_consumption = np.random.uniform(3, 7, n_samples)

# Create a pandas DataFrame
data = pd.DataFrame({
    'Temperature': temperature,
    'Pressure': pressure,
    'Vibration': vibration,
    'Flow Rate': flow_rate,
    'Power Consumption': power_consumption
})

# Inject some anomalies (10% of the data)
anomaly_indices = np.random.choice(n_samples, int(n_samples * 0.1), replace=False)
data.loc[anomaly_indices, 'Temperature'] += np.random.uniform(5, 10, len(anomaly_indices))

# Create a target column indicating whether a sample is an anomaly or not
data['target_column'] = 0
data.loc[anomaly_indices, 'target_column'] = 1

# Save the dataset to a CSV file
data.to_csv('models/anomaly_detection_data.csv', index=False)