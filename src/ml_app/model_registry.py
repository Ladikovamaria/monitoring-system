from pathlib import Path


class ModelRegistry:
    """
    Реестр путей к файлам моделей, scaler и метаданных.

    Для каждого VLAN хранятся:
    - модель: .keras
    - scaler: .pkl
    - meta: .pkl
    """

    def __init__(self, base_dir: str = "models"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def get_paths(self, vlan_id: int) -> dict:
        vlan_prefix = f"vlan_{vlan_id}"

        return {
            "model_path": self.base_dir / f"{vlan_prefix}.keras",
            "scaler_path": self.base_dir / f"{vlan_prefix}_scaler.pkl",
            "meta_path": self.base_dir / f"{vlan_prefix}_meta.pkl",
        }

    def model_exists(self, vlan_id: int) -> bool:
        paths = self.get_paths(vlan_id)
        return (
            paths["model_path"].exists()
            and paths["scaler_path"].exists()
            and paths["meta_path"].exists()
        )

    def list_available_vlans(self) -> list[int]:
        vlans = set()

        for file_path in self.base_dir.glob("vlan_*_meta.pkl"):
            name = file_path.stem  # например vlan_10_meta
            parts = name.split("_")
            if len(parts) >= 3:
                try:
                    vlan_id = int(parts[1])
                    vlans.add(vlan_id)
                except ValueError:
                    continue

        return sorted(vlans)