import numpy as np
import pandas as pd
import joblib

from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import LSTM, Dense, RepeatVector, TimeDistributed, Input
from tensorflow.keras.callbacks import EarlyStopping
from sklearn.preprocessing import MinMaxScaler


class NetworkAnomalyDetector:
    """
    LSTM Autoencoder для обнаружения аномалий в многомерных временных рядах.

    Логика:
    - модель обучается на нормальном трафике
    - учится восстанавливать типичные окна метрик
    - для новых окон считается reconstruction error
    - если ошибка выше threshold, окно считается аномальным
    """

    def __init__(self, window_size=30, feature_columns=None):
        self.window_size = window_size
        self.feature_columns = feature_columns or []
        self.n_features = len(self.feature_columns)

        if self.n_features == 0:
            raise ValueError("feature_columns не должен быть пустым")

        self.scaler = MinMaxScaler()
        self.threshold = None
        self.model = self._build_model()

    def _build_model(self):
        model = Sequential([
            Input(shape=(self.window_size, self.n_features)),
            LSTM(64, activation="tanh", return_sequences=False),
            RepeatVector(self.window_size),
            LSTM(64, activation="tanh", return_sequences=True),
            TimeDistributed(Dense(self.n_features))
        ])
        model.compile(optimizer="adam", loss="mse")
        return model

    def _prepare_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        if df is None or df.empty:
            raise ValueError("Передан пустой DataFrame")

        missing_cols = [col for col in self.feature_columns if col not in df.columns]
        if missing_cols:
            raise ValueError(f"В DataFrame отсутствуют колонки: {missing_cols}")

        prepared = df.copy()
        prepared = prepared.dropna(subset=self.feature_columns)

        if len(prepared) < self.window_size:
            raise ValueError(
                f"Недостаточно данных после удаления пропусков: "
                f"{len(prepared)} строк, window_size={self.window_size}"
            )

        return prepared

    def _create_sequences(self, data: np.ndarray) -> np.ndarray:
        if len(data) < self.window_size:
            raise ValueError(
                f"Недостаточно данных для формирования окон: "
                f"{len(data)} < {self.window_size}"
            )

        sequences = []
        for i in range(len(data) - self.window_size + 1):
            sequences.append(data[i:i + self.window_size])

        return np.array(sequences)

    def fit(
        self,
        df_metrics: pd.DataFrame,
        threshold_quantile: float = 0.95,
        epochs: int = 50,
        batch_size: int = 32,
    ) -> dict:
        """
        Обучение модели на нормальном трафике.

        Возвращает словарь:
        - history
        - train_reconstruction_error
        - threshold
        """
        print("[fit] preparing dataframe...")
        df_prepared = self._prepare_dataframe(df_metrics)
        print(f"[fit] prepared shape = {df_prepared.shape}")

        data = df_prepared[self.feature_columns].values
        print(f"[fit] raw data shape = {data.shape}")
        print(f"[fit] raw data dtype = {data.dtype}")
        data_scaled = self.scaler.fit_transform(data)
        print(f"[fit] scaled shape = {data_scaled.shape}")
        print(f"[fit] scaled min = {np.min(data_scaled)}, max = {np.max(data_scaled)}")
        x_train = self._create_sequences(data_scaled)
        print(f"[fit] x_train shape = {x_train.shape}")
        print(f"[fit] x_train dtype = {x_train.dtype}")

        early_stopping = EarlyStopping(
            monitor="val_loss",
            patience=5,
            restore_best_weights=True
        )

        print("[fit] starting model.fit()...")
        history = self.model.fit(
            x_train,
            x_train,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=0.1,
            callbacks=[early_stopping],
            verbose=1
        )

        reconstructed = self.model.predict(x_train, verbose=0)
        reconstruction_error = np.mean((x_train - reconstructed) ** 2, axis=(1, 2))

        self.threshold = float(np.quantile(reconstruction_error, threshold_quantile))

        return {
            "history": history.history,
            "train_reconstruction_error": reconstruction_error,
            "threshold": self.threshold,
        }

    def detect_anomalies(self, df_new: pd.DataFrame) -> pd.DataFrame:
        """
        Анализ новых данных уже обученной моделью.

        Возвращает DataFrame, где каждой строке соответствует конец окна:
        - исходные поля
        - anomaly_score
        - is_anomaly
        """
        if self.threshold is None:
            raise ValueError("Модель не обучена: threshold отсутствует")

        df_prepared = self._prepare_dataframe(df_new)

        data = df_prepared[self.feature_columns].values
        data_scaled = self.scaler.transform(data)

        x = self._create_sequences(data_scaled)

        reconstructed = self.model.predict(x, verbose=0)
        reconstruction_error = np.mean((x - reconstructed) ** 2, axis=(1, 2))
        anomalies = reconstruction_error > self.threshold

        result = df_prepared.iloc[self.window_size - 1:].copy().reset_index(drop=True)
        result["anomaly_score"] = reconstruction_error
        result["is_anomaly"] = anomalies

        return result

    def score_last_window(self, df_new: pd.DataFrame) -> dict:
        """
        Удобный метод для online-режима:
        берёт последние window_size строк и возвращает score только для последнего окна.
        """
        if self.threshold is None:
            raise ValueError("Модель не обучена: threshold отсутствует")

        df_prepared = self._prepare_dataframe(df_new)

        if len(df_prepared) < self.window_size:
            raise ValueError(
                f"Недостаточно данных для score_last_window: "
                f"{len(df_prepared)} < {self.window_size}"
            )

        df_last = df_prepared.tail(self.window_size).copy()

        data = df_last[self.feature_columns].values
        data_scaled = self.scaler.transform(data)
        x = np.expand_dims(data_scaled, axis=0)

        reconstructed = self.model.predict(x, verbose=0)
        reconstruction_error = float(np.mean((x - reconstructed) ** 2))
        is_anomaly = reconstruction_error > self.threshold

        last_row = df_last.iloc[-1]

        result = {
            "anomaly_score": reconstruction_error,
            "is_anomaly": bool(is_anomaly),
        }

        if "timestamp" in df_last.columns:
            result["timestamp"] = last_row["timestamp"]

        if "vlan_id" in df_last.columns:
            result["vlan_id"] = last_row["vlan_id"]

        return result

    def save(self, model_path: str, scaler_path: str, meta_path: str):
        if self.threshold is None:
            raise ValueError("Нельзя сохранить detector без threshold. Сначала вызови fit().")

        self.model.save(model_path)
        joblib.dump(self.scaler, scaler_path)

        meta = {
            "window_size": self.window_size,
            "feature_columns": self.feature_columns,
            "threshold": self.threshold,
        }
        joblib.dump(meta, meta_path)

    @classmethod
    def load(cls, model_path: str, scaler_path: str, meta_path: str):
        meta = joblib.load(meta_path)

        detector = cls(
            window_size=meta["window_size"],
            feature_columns=meta["feature_columns"],
        )
        detector.model = load_model(model_path)
        detector.scaler = joblib.load(scaler_path)
        detector.threshold = meta["threshold"]

        return detector