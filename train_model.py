

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import os
import re
from urllib.parse import urlparse

# Create model directory
if not os.path.exists('model'):
    os.makedirs('model')

def extract_features(url):
    """Extract 18 features from URL"""
    features = {}
    
    try:
        # Add https:// if no protocol specified and it's a well-known domain
        if not url.startswith(('http://', 'https://')):
            # Check if it's a well-known domain
            well_known = ['google', 'facebook', 'amazon', 'youtube', 'wikipedia', 
                         'twitter', 'instagram', 'linkedin', 'github', 'microsoft',
                         'apple', 'netflix', 'reddit', 'stackoverflow']
            if any(domain in url.lower() for domain in well_known):
                url = 'https://' + url
            else:
                url = 'http://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Basic features
        features['url_length'] = len(url)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_at'] = url.count('@')
        features['num_question'] = url.count('?')
        features['num_ampersand'] = url.count('&')
        features['num_equal'] = url.count('=')
        
        # IP address detection
        ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
        features['has_ip'] = 1 if ip_pattern.search(domain) else 0
        
        # HTTPS check (but don't penalize well-known domains)
        features['has_https'] = 1 if parsed.scheme == 'https' else 0
        
        # Domain features
        features['domain_length'] = len(domain)
        features['num_subdomains'] = domain.count('.') - 1 if domain.count('.') > 0 else 0
        
        # Suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.cc', '.pw', '.xyz', '.top', '.work']
        features['suspicious_tld'] = 1 if any(tld in url.lower() for tld in suspicious_tlds) else 0
        
        # Path features
        path = parsed.path
        features['path_length'] = len(path)
        
        # Suspicious keywords (only in path, not domain)
        keywords = ['login', 'verify', 'account', 'secure', 'banking', 'update', 
                   'confirm', 'password', 'signin', 'suspended', 'locked', 'urgent']
        features['has_suspicious_keyword'] = 1 if any(kw in path.lower() for kw in keywords) else 0
        
        # Special character ratio
        special_chars = sum(1 for c in url if not c.isalnum())
        features['special_char_ratio'] = special_chars / len(url) if len(url) > 0 else 0
        
        # Number of digits in domain (not entire URL)
        features['num_digits'] = sum(c.isdigit() for c in domain)
        
    except Exception as e:
        print(f"Error extracting features from {url}: {e}")
        return None
    
    return features

def main():
    print("\n" + "="*70)
    print("PHISHING URL DETECTOR - MODEL TRAINING")
    print("="*70)
    
    # Load dataset
    print("\n Loading dataset...")
    
    if not os.path.exists('phishing_dataset.csv'):
        print("\n ERROR: phishing_dataset.csv not found!")
        print("Please ensure the dataset file is in the same directory.")
        return
    
    df = pd.read_csv('phishing_dataset.csv')
    print(f"✓ Dataset loaded: {len(df)} URLs")
    
    # Dataset info
    print(f"\n DATASET STATISTICS")
    print("-" * 70)
    print(f"Total URLs: {len(df)}")
    print(f"Legitimate: {sum(df['label']==0)} ({sum(df['label']==0)/len(df)*100:.1f}%)")
    print(f"Phishing: {sum(df['label']==1)} ({sum(df['label']==1)/len(df)*100:.1f}%)")
    
    # Sample URLs
    print(f"\n SAMPLE URLs")
    print("-" * 70)
    print("\nLegitimate (5 samples):")
    for url in df[df['label']==0]['url'].head(5):
        print(f"  ✓ {url}")
    
    print("\nPhishing (5 samples):")
    for url in df[df['label']==1]['url'].head(5):
        print(f"  {url}")
    
    # Extract features
    print(f"\n EXTRACTING FEATURES")
    print("-" * 70)
    print("Processing URLs...")
    
    features_list = []
    for idx, url in enumerate(df['url']):
        if (idx + 1) % 100 == 0:
            print(f"  Processed: {idx + 1}/{len(df)}")
        
        feat = extract_features(url)
        if feat is None:
            feat = {k: 0 for k in ['url_length', 'num_dots', 'num_hyphens', 
                   'num_underscores', 'num_slashes', 'num_at', 'num_question',
                   'num_ampersand', 'num_equal', 'has_ip', 'has_https',
                   'domain_length', 'num_subdomains', 'suspicious_tld',
                   'path_length', 'has_suspicious_keyword', 'special_char_ratio',
                   'num_digits']}
        features_list.append(feat)
    
    print(f"✓ Feature extraction complete!")
    
    # Create feature matrix
    X = pd.DataFrame(features_list)
    y = df['label']
    
    print(f"\n FEATURES: {len(X.columns)} total")
    print(f"Features: {list(X.columns)}")
    
    # Train/test split
    print(f"\n  SPLITTING DATA")
    print("-" * 70)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Training: {len(X_train)} samples")
    print(f"Testing: {len(X_test)} samples")
    
    # Scale features
    print(f"\n  SCALING FEATURES")
    print("-" * 70)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    print("✓ Features scaled using StandardScaler")
    
    # Train model
    print(f"\n TRAINING RANDOM FOREST")
    print("-" * 70)
    print("Configuration: 100 trees, max_depth=20")
    
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_train_scaled, y_train)
    print("✓ Training complete!")
    
    # Evaluate
    print(f"\n MODEL EVALUATION")
    print("-" * 70)
    y_pred = model.predict(X_test_scaled)
    
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\n ACCURACY: {accuracy:.4f} ({accuracy*100:.2f}%)")
    
    print(f"\n CLASSIFICATION REPORT")
    print("-" * 70)
    print(classification_report(y_test, y_pred, 
                                target_names=['Legitimate', 'Phishing'],
                                digits=4))
    
    # Confusion matrix
    print(f"\n CONFUSION MATRIX")
    print("-" * 70)
    cm = confusion_matrix(y_test, y_pred)
    print(f"\n              Predicted")
    print(f"            Legit  Phishing")
    print(f"Actual Legit  {cm[0][0]:4d}    {cm[0][1]:4d}")
    print(f"      Phish   {cm[1][0]:4d}    {cm[1][1]:4d}")
    
    print(f"\nTrue Negatives: {cm[0][0]}")
    print(f"False Positives: {cm[0][1]}")
    print(f"False Negatives: {cm[1][0]}")
    print(f"True Positives: {cm[1][1]}")
    
    # Feature importance
    print(f"\n TOP 10 FEATURES")
    print("-" * 70)
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    for idx, row in feature_importance.head(10).iterrows():
        bar = '█' * int(row['importance'] * 100)
        print(f"{row['feature']:25s} {row['importance']:.4f} {bar}")
    
    # Save model
    print(f"\n SAVING MODEL")
    print("-" * 70)
    joblib.dump(model, 'model/phishing_model.pkl')
    joblib.dump(scaler, 'model/scaler.pkl')
    joblib.dump(list(X.columns), 'model/feature_names.pkl')
    print("✓ Saved: model/phishing_model.pkl")
    print("✓ Saved: model/scaler.pkl")
    print("✓ Saved: model/feature_names.pkl")
    
    # Test samples
    print(f"\n TESTING SAMPLES")
    print("-" * 70)
    
    test_urls = [
        ("https://www.google.com", "SAFE"),
        ("http://paypal-verify.tk/login", "PHISHING"),
        ("https://www.jinnah.edu", "SAFE"),
        ("http://192.168.1.1/secure", "PHISHING"),
    ]
    
    for url, expected in test_urls:
        feat = extract_features(url)
        feat_array = np.array([[feat[name] for name in X.columns]])
        feat_scaled = scaler.transform(feat_array)
        pred = model.predict(feat_scaled)[0]
        prob = model.predict_proba(feat_scaled)[0]
        
        result = "SAFE" if pred == 0 else "PHISHING"
        confidence = max(prob) * 100
        
        status = "✓" if expected == result else "✗"
        print(f"\n{status} {url}")
        print(f"  Expected: {expected} | Got: {result} ({confidence:.1f}%)")
    
    # Summary
    print(f"\n" + "="*70)
    print("✅ TRAINING COMPLETED!")
    print("="*70)
    print(f"\nAccuracy: {accuracy*100:.2f}%")
    print(f"Model saved in: model/")
    print(f"\n▶️  Next: Run Flask app")
    print(f"   python app.py")
    print(f"   http://localhost:5000")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()