
import joblib
import pandas as pd

from app.ml.live_feature_extractor import extract_live_features


# LOAD TRAINED MODEL

model = joblib.load("app/ml/phishing_model.pkl")


# LABEL MAPPING

LABELS = {

    0: "safe",

    1: "defacement",

    2: "phishing",

    3: "malware"
}


def predict_url(url):

    try:

        # EXTRACT FEATURES

        features = extract_live_features(url)

        # CONVERT TO DATAFRAME
        # IMPORTANT:
        # Keeps feature names aligned with training

        feature_df = pd.DataFrame(

            [features],

            columns=model.feature_names_in_
        )

        # PREDICTION

        prediction = model.predict(feature_df)[0]

        # PROBABILITIES

        probabilities = model.predict_proba(
            feature_df
        )[0]

        # CONFIDENCE SCORE

        confidence = float(

            round(

                max(probabilities) * 100,

                2
            )
        )

        # FORMAT PROBABILITIES

        probability_scores = {

            LABELS[i]: float(

                round(prob * 100, 2)

            )

            for i, prob in enumerate(probabilities)
        }

        return {

            "prediction": LABELS.get(

                int(prediction),

                "unknown"
            ),

            "confidence": confidence,

            "probabilities": probability_scores
        }

    except Exception as e:

        return {

            "prediction": "error",

            "confidence": 0,

            "probabilities": {},

            "error": str(e)
        }

