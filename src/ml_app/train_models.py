from src.ml_app.db_reader import MetricsDBReader

from src.ml_app.model_registry import ModelRegistry


DB_URL = "postgresql+psycopg2://monitsys_user:12345@localhost:5432/monitsys"
TABLE_NAME = "features"
MODEL_DIR = "models"
WINDOW_SIZE = 30

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
    print("Start trainig")
    db_reader = MetricsDBReader(
        db_url=DB_URL,
        table_name=TABLE_NAME,
    )
    print("End of DB reading")

    registry = ModelRegistry(base_dir=MODEL_DIR)
    print("Succesfully loaded models")
    vlan_ids = db_reader.get_available_vlans()
    print(f"[train] found VLANs: {vlan_ids}")

    if not vlan_ids:
        print("[train] no VLANs found in database")
        return

    for vlan_id in vlan_ids:
        from src.ml_app.anomaly_detector import NetworkAnomalyDetector
        print(f"[train] processing VLAN {vlan_id} ...")

        df = db_reader.load_training_data(vlan_id=vlan_id)
        print(f"[train] VLAN {vlan_id}: dataframe shape = {df.shape}")
        print(f"[train] VLAN {vlan_id}: columns = {list(df.columns)}")
        print(f"[train] VLAN {vlan_id}: nulls =")
        print(df[FEATURE_COLUMNS].isnull().sum())
        print(f"[train] VLAN {vlan_id}: dtypes =")
        print(df[FEATURE_COLUMNS].dtypes)
        print(f"[train] VLAN {vlan_id}: head =")
        print(df[FEATURE_COLUMNS].head())

        if df.empty:
            print(f"[train] VLAN {vlan_id}: no data, skipped")
            continue

        print(f"[train] VLAN {vlan_id}: loaded {len(df)} rows")

        detector = NetworkAnomalyDetector(
            window_size=WINDOW_SIZE,
            feature_columns=FEATURE_COLUMNS,
        )

        train_result = detector.fit(df)

        print(
            f"[train] VLAN {vlan_id}: threshold={train_result['threshold']:.6f}"
        )

        paths = registry.get_paths(vlan_id)

        detector.save(
            model_path=str(paths["model_path"]),
            scaler_path=str(paths["scaler_path"]),
            meta_path=str(paths["meta_path"]),
        )

        print(f"[train] VLAN {vlan_id}: model saved")
        print(f"         model:  {paths['model_path']}")
        print(f"         scaler: {paths['scaler_path']}")
        print(f"         meta:   {paths['meta_path']}")

    print("[train] done")


if __name__ == "__main__":
    main()