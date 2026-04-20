import time

from src.ml_app.db_reader import MetricsDBReader

from src.ml_app.model_registry import ModelRegistry


DB_URL = "postgresql+psycopg2://monitsys_user:12345@localhost:5432/monitsys"
TABLE_NAME = "features"
MODEL_DIR = "models"

WINDOW_SIZE = 30
POLL_INTERVAL = 10  # секунд

FEATURE_COLUMNS = [
    "bytes_per_sec",
    "frames_per_sec",
    "broadcast_ratio",
    "arp_per_sec",
    "active_ip_count",
    "active_flow_count",
    "iat_mean",
    "iat_std",
    "snmp_in_errors_rate",
    "snmp_out_errors_rate",
    "snmp_discards_rate",
    "snmp_cpu",
]


def main():
    db_reader = MetricsDBReader(DB_URL, TABLE_NAME)
    registry = ModelRegistry(MODEL_DIR)

    print("[detect] starting anomaly detection loop...")

    while True:
        vlan_ids = db_reader.get_available_vlans()

        if not vlan_ids:
            print("[detect] no VLANs found, sleeping...")
            time.sleep(POLL_INTERVAL)
            continue

        for vlan_id in vlan_ids:
            from src.ml_app.anomaly_detector import NetworkAnomalyDetector
            try:
                if not registry.model_exists(vlan_id):
                    print(f"[detect] VLAN {vlan_id}: model not found, skipping")
                    continue

                paths = registry.get_paths(vlan_id)

                detector = NetworkAnomalyDetector.load(
                    model_path=str(paths["model_path"]),
                    scaler_path=str(paths["scaler_path"]),
                    meta_path=str(paths["meta_path"]),
                )

                df_last = db_reader.load_last_window(
                    vlan_id=vlan_id,
                    window_size=WINDOW_SIZE,
                )

                if len(df_last) < WINDOW_SIZE:
                    print(f"[detect] VLAN {vlan_id}: not enough data")
                    continue

                result = detector.score_last_window(df_last)

                print(
                    f"[detect] VLAN {vlan_id} | "
                    f"score={result['anomaly_score']:.6f} | "
                    f"anomaly={result['is_anomaly']}"
                )

                # 👉 позже можно писать это в БД

            except Exception as e:
                print(f"[detect] VLAN {vlan_id} error: {e}")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()