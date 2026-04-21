from pathlib import Path
import pandas as pd
from urllib.parse import urlparse
import time
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction import DictVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report

from features import extract_features

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR.parent / "data" / "dataseturl.csv"
MODEL_PATH = BASE_DIR / "model.joblib"

def main():

    print("Training Start!")

    df = pd.read_csv(DATA_PATH)

    df.columns = df.columns.str.strip().str.lower()

    df = df.dropna(subset=["url","label"])

    df["url"] = df["url"].astype(str).str.strip()

    df["label"] = df["label"].astype(str).str.strip().str.lower()

    df = df.drop_duplicates(subset=["url"])

    print(df["label"].value_counts())


    # ======================
    # BALANCING 160000
    # ======================

    TARGET = 160000

    parts = []

    for lbl in [
        "benign",
        "phishing",
        "potential_risky",
        "malware"
    ]:

        d = df[df["label"] == lbl]

        if len(d) > TARGET:

            d = d.sample(
                TARGET,
                random_state=42
            )

        parts.append(d)


    df = pd.concat(parts).sample(
        frac=1,
        random_state=42
    )


    print("Sesudah balancing:")

    print(df["label"].value_counts())

    print(df["label"].value_counts())

    df.columns = df.columns.str.lower().str.strip()

    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("CSV harus punya kolom: url dan label")

    df["label"] = df["label"].astype(str).str.lower().str.strip()
    label_mapping = {
        "benign": 0,
        "phishing": 1,
        "malware": 2,
        "potential_risky": 3,
    }

    y = df["label"].map(label_mapping)
    if y.isna().any():
        bad = df.loc[y.isna(), "label"].unique()
        raise ValueError(f"Ada label tidak dikenali: {bad}")

    X = [extract_features(url) for url in df["url"].astype(str)]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y.values, test_size=0.2, random_state=42, stratify=y
    )

    base_model = LogisticRegression(
        max_iter=9000,
        solver="lbfgs",
    )
    model = Pipeline([
        ("vec", DictVectorizer(sparse=False)),
        ("scale", StandardScaler()),
        ("clf", CalibratedClassifierCV(
            estimator=base_model,
            method="sigmoid",
            cv=3
        ))
    ])

    print("Memulai Training...")
    start = time.time()
    model.fit(X_train, y_train)

    end = time.time()
    print("Training Selesai!")
    print("Training Time:", round(end - start, 2), "seconds")

    predictions = model.predict(X_test)
    print(
        classification_report(
            y_test,
            predictions,
            labels=[0, 1, 2, 3],
            target_names=["benign", "phishing", "malware", "potential_risky"],
            zero_division=0
        )
    )

    joblib.dump(model, MODEL_PATH)
    print(f"Model berhasil disimpan ke {MODEL_PATH}")
    print("Training Done!")

if __name__ == "__main__":
    main()