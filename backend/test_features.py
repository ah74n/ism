from app.ml.feature_extractor import extract_features

url = "paypal-login-secure.xyz"

features = extract_features(url)

print(features)