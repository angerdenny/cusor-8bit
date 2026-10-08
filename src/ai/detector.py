"""Isolation Forest 기반 네트워크 이상 감지기."""
from __future__ import annotations

import threading
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURES = ("cpu", "ram", "traffic", "ping", "loss")
LABELS = {"cpu": "CPU", "ram": "메모리", "traffic": "트래픽", "ping": "지연(Ping)", "loss": "패킷 손실"}

MODEL_PATH = Path(__file__).resolve().parent / "models" / "baseline.joblib"
MIN_SAMPLES = 50          # 이보다 적으면 학습하지 않음
SENSITIVITY = 20.0        # 클수록 위험도가 0/100 쪽으로 급격히 갈림
ANOMALY_THRESHOLD = 60.0  # 위험 스코어가 이 값 이상이면 이상으로 판단
MAX_BASELINE = 20000      # 기준선 데이터 최대 보관 수


class NetworkAnomalyDetector:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._model: IsolationForest | None = None
        self._scaler: StandardScaler | None = None
        self._baseline = np.empty((0, len(FEATURES)))
        self._load()

    # ---------- 유틸 ----------
    @staticmethod
    def _vec(row: dict) -> list[float]:
        return [float(row.get(k) or 0) for k in FEATURES]

    @property
    def trained(self) -> bool:
        return self._model is not None

    # ---------- 학습 ----------
    def train_baseline(self, rows: list[dict]) -> int:
        """평시 텔레메트리로 정상 기준선을 학습한다. 학습에 쓴 샘플 수를 반환."""
        X = np.array([self._vec(r) for r in rows], dtype=float)
        if len(X) < MIN_SAMPLES:
            raise ValueError(f"학습 데이터가 부족합니다 ({len(X)}/{MIN_SAMPLES})")
        with self._lock:
            self._fit(X[-MAX_BASELINE:])
        return len(X)

    def _fit(self, X: np.ndarray) -> None:
        scaler = StandardScaler().fit(X)
        model = IsolationForest(
            n_estimators=200, contamination=0.01, random_state=42
        ).fit(scaler.transform(X))
        self._scaler, self._model, self._baseline = scaler, model, X
        self._save()

    # ---------- 추론 ----------
    def predict_risk(self, sample: dict) -> dict:
        """risk_score(0~100), is_anomaly, 가장 크게 벗어난 항목을 반환."""
        x = np.array([self._vec(sample)], dtype=float)
        with self._lock:
            if not self.trained:  # 미학습 시 기존 임시 수식으로 대체
                cpu, ram, loss = x[0][0], x[0][1], x[0][4]
                risk = float(np.clip(cpu * 0.5 + ram * 0.2 + loss * 0.3, 0, 100))
                return {"risk_score": round(risk, 1), "is_anomaly": risk >= ANOMALY_THRESHOLD,
                        "top_factor": None, "trained": False}

            z = self._scaler.transform(x)
            d = float(self._model.decision_function(z)[0])  # 양수=정상, 음수=이상
            risk = 100.0 / (1.0 + np.exp(np.clip(SENSITIVITY * d, -50, 50)))
            top = FEATURES[int(np.argmax(np.abs(z[0])))]
            return {"risk_score": round(float(risk), 1),
                    "is_anomaly": bool(risk >= ANOMALY_THRESHOLD),
                    "top_factor": LABELS[top], "trained": True}

    # ---------- 피드백 재학습 ----------
    def add_feedback(self, sample: dict, copies: int = 30) -> int:
        """오탐으로 판정된 샘플을 정상 데이터에 반영하고 재학습한다.
        1건만 넣으면 영향이 거의 없어서, 약간의 노이즈를 준 복제본을 함께 넣는다."""
        base = np.array(self._vec(sample), dtype=float)
        rng = np.random.default_rng()
        noise = rng.normal(0, 0.01, (copies, len(FEATURES))) * np.maximum(np.abs(base), 1.0)
        new = np.clip(base + noise, 0, None)
        with self._lock:
            X = np.vstack([self._baseline, new]) if len(self._baseline) else new
            if len(X) < MIN_SAMPLES:
                raise ValueError("기준선이 아직 학습되지 않았습니다")
            self._fit(X[-MAX_BASELINE:])
            return len(X)

    # ---------- 저장/로드 ----------
    def _save(self) -> None:
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self._model, "scaler": self._scaler, "baseline": self._baseline}, MODEL_PATH)

    def _load(self) -> None:
        if MODEL_PATH.exists():
            try:
                d = joblib.load(MODEL_PATH)
                self._model, self._scaler, self._baseline = d["model"], d["scaler"], d["baseline"]
            except Exception as e:  # 손상된 모델 파일은 무시하고 재학습하게 둠
                print(f"[detector] 모델 로드 실패: {e}")


detector = NetworkAnomalyDetector()