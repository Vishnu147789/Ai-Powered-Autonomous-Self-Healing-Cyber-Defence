"""Machine-learning anomaly detection using IsolationForest."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Sequence

import joblib
from sklearn.ensemble import IsolationForest
from sklearn.exceptions import NotFittedError

from src.config.settings import settings

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """IsolationForest-based detector for identifying anomalous traffic patterns.

    The detector supports training, single-sample prediction, and model
    persistence using joblib.
    """

    def __init__(
        self,
        model_path: str | Path | None = None,
        *,
        contamination: float = 0.05,
        random_state: int = 42,
    ) -> None:
        """Initialize the anomaly detector.

        Args:
            model_path: Optional model file path for save/load operations.
                Defaults to ``settings.MODEL_PATH``.
            contamination: Expected fraction of anomalies in training data.
            random_state: Random seed for reproducibility.
        """
        self.model_path = Path(model_path or settings.MODEL_PATH)
        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )

    def train(self, data: list[list[float]]) -> None:
        """Train the IsolationForest model.

        Args:
            data: Two-dimensional feature matrix where each inner list
                represents one observation.

        Raises:
            ValueError: If data is empty.
        """
        if not data:
            raise ValueError("Training data cannot be empty.")

        logger.info("Training anomaly detector on %d samples", len(data))
        self.model.fit(data)
        logger.info("Anomaly detector training completed")

    def predict(self, sample: list[float]) -> bool:
        """Predict whether a sample is anomalous.

        Args:
            sample: A single feature vector.

        Returns:
            ``True`` when the sample is classified as an anomaly, otherwise ``False``.

        Raises:
            ValueError: If sample is empty.
            RuntimeError: If the model has not been trained/loaded yet.
        """
        if not sample:
            raise ValueError("Sample cannot be empty.")

        try:
            prediction = self.model.predict([sample])[0]
        except NotFittedError as exc:
            raise RuntimeError(
                "Model is not trained. Train the model or load a saved model first."
            ) from exc

        is_anomaly = prediction == -1
        logger.debug("Prediction complete: is_anomaly=%s", is_anomaly)
        return is_anomaly

    def save_model(self, path: str | Path | None = None) -> Path:
        """Persist the trained model to disk.

        Args:
            path: Optional override save path.

        Returns:
            The resolved output path where the model was saved.
        """
        target_path = Path(path) if path is not None else self.model_path
        target_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, target_path)
        logger.info("Anomaly model saved to %s", target_path)
        return target_path

    def load_model(self, path: str | Path | None = None) -> bool:
        """Load a previously saved model from disk.

        Args:
            path: Optional override load path.

        Returns:
            ``True`` if model file was loaded successfully, ``False`` if file
            does not exist.

        Raises:
            RuntimeError: If model loading fails for a non-file-not-found reason.
        """
        source_path = Path(path) if path is not None else self.model_path
        if not source_path.exists():
            logger.warning("Model file not found at %s", source_path)
            return False

        try:
            loaded_model = joblib.load(source_path)
            if not isinstance(loaded_model, IsolationForest):
                raise TypeError(
                    f"Loaded model type {type(loaded_model)!r} is not IsolationForest."
                )
            self.model = loaded_model
            logger.info("Anomaly model loaded from %s", source_path)
            return True
        except Exception as exc:  # pragma: no cover - filesystem/corruption dependent
            logger.exception("Failed to load model from %s: %s", source_path, exc)
            raise RuntimeError(f"Unable to load model from {source_path}") from exc
