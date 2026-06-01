import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report


# LOAD DATASET

df = pd.read_csv("dataset/url_data.csv")

print("Dataset Loaded:", len(df))


# REMOVE NON-NUMERIC COLUMNS

# DROP NON-ML COLUMNS

drop_columns = [

    "url",
    "type",
    "label",
    "domain",
    "Date_inspection"
]

# REMOVE BAD LABEL ROWS

df = df.dropna(subset=["label"])

# FORCE INTEGER LABELS

df["label"] = df["label"].astype(int)

# FEATURES

X = df.drop(columns=drop_columns)

# FILL MISSING VALUES

X = X.fillna(0)

# TARGET

y = df["label"]


# TRAIN TEST SPLIT

X_train, X_test, y_train, y_test = train_test_split(

    X,
    y,

    test_size=0.2,

    random_state=42
)


# MODEL

model = RandomForestClassifier(

    n_estimators=300,

    max_depth=25,

    random_state=42,

    n_jobs=-1
)


# TRAIN

print("Training model...")

model.fit(X_train, y_train)

print("Training complete.")


# TEST

predictions = model.predict(X_test)

print(classification_report(y_test, predictions))


# SAVE MODEL

joblib.dump(model, "app/ml/phishing_model.pkl")

print("Model saved successfully.")