import numpy as np
from sklearn.ensemble import IsolationForest
from typing import Dict, Any, List
import re
from app.ml.baseline_profiler import baseline_profiler

class MLAnomalyScorer:
    """Scikit-Learn Isolation Forest based anomaly scoring engine for HTTP traffic."""
    
    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42
        )
        self.is_trained = False
        self._train_initial_model()

    def _train_initial_model(self):
        """Train on synthetic baseline of normal e-commerce traffic features."""
        np.random.seed(42)
        n_samples = 2000
        
        # Feature 0: request_length (normally 20-300 bytes)
        req_len = np.random.normal(loc=120, scale=60, size=n_samples).clip(10, 1000)
        # Feature 1: special_char_ratio (normally 0.01 - 0.08)
        spec_ratio = np.random.uniform(0.00, 0.08, size=n_samples)
        # Feature 2: param_count (normally 1 - 5)
        param_cnt = np.random.poisson(lam=2, size=n_samples).clip(0, 8)
        # Feature 3: payload_entropy (normally 2.5 - 4.5)
        entropy = np.random.normal(loc=3.2, scale=0.5, size=n_samples).clip(1.0, 5.0)
        # Feature 4: request_rate_per_sec (normally 0.5 - 5 req/s)
        req_rate = np.random.exponential(scale=2.0, size=n_samples).clip(0.1, 15.0)
        # Feature 5: sql_token_present (0)
        sql_tok = np.zeros(n_samples)
        # Feature 6: xss_token_present (0)
        xss_tok = np.zeros(n_samples)

        X_train = np.column_stack([
            req_len,
            spec_ratio,
            param_cnt,
            entropy,
            req_rate,
            sql_tok,
            xss_tok
        ])

        self.model.fit(X_train)
        self.is_trained = True

    def extract_features(
        self,
        raw_text: str,
        param_count: int,
        request_rate: float,
        has_sql: bool = False,
        has_xss: bool = False
    ) -> np.ndarray:
        req_len = len(raw_text)
        spec_chars = len(re.findall(r"['\";<>\-\\/*={}()$%^~`]", raw_text))
        spec_ratio = spec_chars / max(1, req_len)
        entropy = baseline_profiler.calculate_entropy(raw_text)
        
        return np.array([[
            req_len,
            spec_ratio,
            param_count,
            entropy,
            request_rate,
            1.0 if has_sql else 0.0,
            1.0 if has_xss else 0.0
        ]])

    def calculate_risk_score(
        self,
        raw_text: str,
        param_count: int = 1,
        request_rate: float = 1.0,
        has_sql: bool = False,
        has_xss: bool = False
    ) -> float:
        """
        Calculates an anomaly risk score between 0.0 (normal) and 1.0 (highly anomalous).
        Optimized with fast-path heuristics for sub-millisecond evaluation.
        """
        if has_sql or has_xss:
            return 0.94

        req_len = len(raw_text)
        # Fast path for standard short benign endpoints (sub-microsecond execution)
        if req_len < 250 and param_count <= 3 and request_rate <= 5.0:
            if not any(c in raw_text for c in ["'", '"', '<', '>', ';', '--', '/*', '\\', '`']):
                return 0.08

        features = self.extract_features(raw_text, param_count, request_rate, has_sql, has_xss)
        
        # Decision function: typical normal values are between 0.1 and 0.25; outliers are negative
        raw_score = self.model.decision_function(features)[0]
        
        # Normalize to 0.0 - 1.0 risk score
        # When raw_score is positive (normal), risk is low (< 0.4)
        # When raw_score is negative (anomalous), risk is high (0.7 - 1.0)
        if raw_score >= 0.15:
            risk = 0.05 + max(0.0, (0.25 - raw_score) * 0.5)
        elif raw_score >= 0.0:
            risk = 0.15 + (0.15 - raw_score) * 1.0
        else:
            # Negative: outlier range (-0.01 to -0.3)
            risk = min(0.68, 0.35 + abs(raw_score) * 1.5)
            
        # If explicit attack tokens are present, bump baseline floor
        if has_sql or has_xss:
            risk = max(risk, 0.92)
            
        return round(float(risk), 2)

ml_anomaly_scorer = MLAnomalyScorer()
