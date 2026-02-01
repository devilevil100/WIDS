import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from xgboost import XGBClassifier
import joblib
import os
from typing import Dict, Tuple, Any, Optional
import warnings
warnings.filterwarnings('ignore')

class FraudClassifier:
    def __init__(self, model_path: str = "fraud_model.joblib"):
        self.model_path = model_path
        self.scaler_path = "scaler.joblib"
        self.model = None
        self.scaler = StandardScaler()
        self.feature_columns = []
        self.best_model_name = None

    def load_and_preprocess_data(self, csv_path: str, sample_size: Optional[int] = None) -> Tuple[pd.DataFrame, pd.Series]:
        if sample_size:
            chunks = []
            for chunk in pd.read_csv(csv_path, chunksize=500000):
                chunks.append(chunk.sample(min(len(chunk), sample_size // 10)))
                if len(pd.concat(chunks)) >= sample_size:
                    break
            df = pd.concat(chunks).head(sample_size)
        else:
            df = pd.read_csv(csv_path)

        df = self._engineer_features(df)

        self.feature_columns = [
            'value_log',
            'hour_of_day',
            'day_of_week',
            'from_address_freq',
            'to_address_freq',
            'value_normalized',
            'block_height_normalized'
        ]

        X = df[self.feature_columns].fillna(0)
        y = df['isError']

        return X, y

    def _engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        if 'Unnamed: 0' in df.columns:
            df = df.drop('Unnamed: 0', axis=1)

        df['Value'] = pd.to_numeric(df['Value'], errors='coerce').fillna(0)
        df['value_log'] = np.log1p(df['Value'])
        df['value_normalized'] = (df['Value'] - df['Value'].mean()) / (df['Value'].std() + 1e-8)

        df['TimeStamp'] = pd.to_numeric(df['TimeStamp'], errors='coerce')
        df['datetime'] = pd.to_datetime(df['TimeStamp'], unit='s', errors='coerce')
        df['hour_of_day'] = df['datetime'].dt.hour.fillna(12)
        df['day_of_week'] = df['datetime'].dt.dayofweek.fillna(0)

        from_counts = df['From'].value_counts()
        to_counts = df['To'].value_counts()
        df['from_address_freq'] = np.log1p(df['From'].map(from_counts).fillna(1))
        df['to_address_freq'] = np.log1p(df['To'].map(to_counts).fillna(1))

        df['BlockHeight'] = pd.to_numeric(df['BlockHeight'], errors='coerce').fillna(0)
        df['block_height_normalized'] = (df['BlockHeight'] - df['BlockHeight'].min()) / (
            df['BlockHeight'].max() - df['BlockHeight'].min() + 1e-8
        )

        return df

    def train(self, X: pd.DataFrame, y: pd.Series) -> Dict[str, Any]:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        models = {
            'Random Forest': RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1,
                class_weight='balanced'
            ),
            'XGBoost': XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=42,
                use_label_encoder=False,
                eval_metric='logloss',
                scale_pos_weight=len(y_train[y_train==0]) / (len(y_train[y_train==1]) + 1)
            ),
            'Gradient Boosting': GradientBoostingClassifier(
                n_estimators=100,
                max_depth=5,
                learning_rate=0.1,
                random_state=42
            ),
            'Logistic Regression': LogisticRegression(
                random_state=42,
                max_iter=1000,
                class_weight='balanced'
            )
        }

        results = {}
        best_score = 0
        best_model = None

        for name, model in models.items():
            if name == 'Logistic Regression':
                model.fit(X_train_scaled, y_train)
                y_pred = model.predict(X_test_scaled)
                y_proba = model.predict_proba(X_test_scaled)[:, 1]
            else:
                model.fit(X_train, y_train)
                y_pred = model.predict(X_test)
                y_proba = model.predict_proba(X_test)[:, 1]

            report = classification_report(y_test, y_pred, output_dict=True)
            roc_auc = roc_auc_score(y_test, y_proba)

            results[name] = {
                'accuracy': report['accuracy'],
                'precision': report['weighted avg']['precision'],
                'recall': report['weighted avg']['recall'],
                'f1_score': report['weighted avg']['f1-score'],
                'roc_auc': roc_auc,
                'confusion_matrix': confusion_matrix(y_test, y_pred).tolist()
            }

            if results[name]['f1_score'] > best_score:
                best_score = results[name]['f1_score']
                best_model = model
                self.best_model_name = name

        self.model = best_model
        return results

    def save_model(self):
        if self.model is None:
            raise ValueError("No model trained yet")

        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'feature_columns': self.feature_columns,
            'model_name': self.best_model_name
        }, self.model_path)

    def load_model(self):
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Model not found at {self.model_path}")

        data = joblib.load(self.model_path)
        self.model = data['model']
        self.scaler = data['scaler']
        self.feature_columns = data['feature_columns']
        self.best_model_name = data['model_name']

    def predict(self, transaction_data: Dict) -> Dict[str, Any]:
        if self.model is None:
            self.load_model()

        value = float(transaction_data.get('value', 0))
        fraud_flags = []

        if value > 10000:
            fraud_flags.append(f"Extreme value: {value:.2e}")
        if value > 1e20:
            fraud_flags.append(f"Impossibly large value: {value:.2e}")

        from_addr = transaction_data.get('from_address', '').lower()
        to_addr = transaction_data.get('to_address', '').lower()
        if from_addr and to_addr and from_addr == to_addr:
            fraud_flags.append("Self-transfer detected")
        if value == 0 and to_addr:
            fraud_flags.append("Zero-value transaction")

        if fraud_flags:
            return {
                'is_fraud': True,
                'fraud_probability': 0.99,
                'legit_probability': 0.01,
                'model_used': 'Rule-Based',
                'rules_triggered': fraud_flags
            }

        features = {
            'value_log': np.log1p(value),
            'hour_of_day': pd.to_datetime(transaction_data.get('timestamp', 0), unit='s').hour,
            'day_of_week': pd.to_datetime(transaction_data.get('timestamp', 0), unit='s').dayofweek,
            'from_address_freq': 1.0,
            'to_address_freq': 1.0,
            'value_normalized': 0.0,
            'block_height_normalized': 0.5
        }

        X = pd.DataFrame([features])[self.feature_columns]
        prediction = self.model.predict(X)[0]
        probability = self.model.predict_proba(X)[0]

        return {
            'is_fraud': bool(prediction),
            'fraud_probability': float(probability[1]),
            'legit_probability': float(probability[0]),
            'model_used': self.best_model_name
        }

def main():
    classifier = FraudClassifier()
    csv_path = "transactions.csv"

    if not os.path.exists(csv_path):
        return

    X, y = classifier.load_and_preprocess_data(csv_path, sample_size=100000)
    results = classifier.train(X, y)
    classifier.save_model()

    sample_tx = {
        'from_address': '0xd551234ae421e3bcba99a0da6d736074f22192ff',
        'to_address': '0x002bf459dc58584d58886169ea0e80f3ca95ffaf',
        'value': 0.58626948,
        'timestamp': 1527017753
    }

    print(classifier.predict(sample_tx))
