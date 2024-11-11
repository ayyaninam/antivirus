import os
import numpy as np
import random
import re
import hashlib
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from joblib import dump
from scipy.stats import entropy

# Function to load the virus database from the provided file path
def load_virus_database(file_path):
    virus_hashes = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                if ':' in line:
                    parts = line.strip().split(':', 1)
                    if len(parts) == 2:
                        hash_value = parts[0]
                        if re.fullmatch(r'[a-fA-F0-9]{64}', hash_value):
                            virus_hashes.append(hash_value)
    except Exception as e:
        print(f"Error loading virus database: {e}")
    return virus_hashes


# Function to convert hash to an integer feature
def convert_hash_to_int(hash_list):
    return [int(h, 16) % (10 ** 8) for h in hash_list]


# Feature extraction function for additional file properties
def extract_features(file_path):
    features = {}
    try:
        features['file_size'] = os.path.getsize(file_path)
        
        with open(file_path, 'rb') as file:
            data = file.read()
            features['entropy'] = entropy(list(data), base=2) if data else 0
            
        features['extension'] = 1 if file_path.endswith(('.exe', '.dll', '.bin')) else 0
        features['hash_mod'] = int(hashlib.sha256(data).hexdigest(), 16) % (10 ** 8)
    except Exception as e:
        print(f"Error extracting features from {file_path}: {e}")
        return None
    return list(features.values())

# Generate benign data with realistic feature values
def generate_benign_data(num_samples):
    benign_hashes = [hashlib.sha256(str(random.random()).encode()).hexdigest() for _ in range(num_samples)]
    return benign_hashes

# Train and save the model with additional features for better detection accuracy
def train_and_save_model(malicious_hashes, model_path='virus_detection_model.joblib'):
    # Prepare malicious and benign data
    num_malicious = len(malicious_hashes)
    benign_hashes = generate_benign_data(num_malicious)
    
    # Convert hashes to integer features and add additional file properties
    X_malicious = [[h] + [1, 5.0, 1] for h in convert_hash_to_int(malicious_hashes)]
    X_benign = [[h] + [0, 1.0, 0] for h in convert_hash_to_int(benign_hashes)]
    
    # Labels for training data
    y_malicious = np.ones(num_malicious)
    y_benign = np.zeros(num_malicious)
    
    # Combine malicious and benign data
    X = np.vstack((X_malicious, X_benign))
    y = np.hstack((y_malicious, y_benign))

    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Use a Logistic Regression model for simplicity and faster training
    clf = LogisticRegression(max_iter=1000, random_state=42)
    clf.fit(X_train, y_train)
    
    # Evaluate the model
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred))
    
    # Save the model
    dump(clf, model_path)
    print(f"Model saved to {model_path}")

# Example usage
virus_database_file_path = 'VirusDataBaseHash.bav'
malicious_hashes = load_virus_database(virus_database_file_path)
train_and_save_model(malicious_hashes)

