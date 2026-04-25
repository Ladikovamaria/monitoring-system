import pandas as pd
from sqlalchemy import create_engine, text


class MetricsDBReader:
    """
    Чтение метрик из PostgreSQL для ML-модуля.

    Позволяет:
    - получить список VLAN
    - загрузить исторические данные для обучения
    - загрузить последние N строк для online-detect
    """

    def __init__(self, db_url: str, table_name: str):
        self.db_url = db_url
        self.table_name = table_name
        self.engine = create_engine(self.db_url)

    def get_available_vlans(self) -> list[int]:
        query = text(f"""
            SELECT DISTINCT vlan_id
            FROM {self.table_name}
            ORDER BY vlan_id
        """)

        with self.engine.connect() as conn:
            result = conn.execute(query)
            vlans = [row[0] for row in result.fetchall()]

        return vlans

    def load_training_data(
        self,
        vlan_id: int,
        limit: int | None = None,
    ) -> pd.DataFrame:
        """
        Загружает исторические данные для обучения по VLAN.
        Всегда сортирует по timestamp.
        """

        if limit is None:
            query = text(f"""
                SELECT *
                FROM {self.table_name}
                WHERE vlan_id = :vlan_id
                ORDER BY timestamp
            """)
            params = {"vlan_id": vlan_id}
        else:
            # Берём последние limit строк, затем пересортировываем по времени вверх
            query = text(f"""
                SELECT *
                FROM (
                    SELECT *
                    FROM {self.table_name}
                    WHERE vlan_id = :vlan_id
                    ORDER BY timestamp DESC
                    LIMIT :limit
                ) AS sub
                ORDER BY timestamp
            """)
            params = {"vlan_id": vlan_id, "limit": limit}

        df = pd.read_sql(query, self.engine, params=params)
        return df

    def load_last_window(
        self,
        vlan_id: int,
        window_size: int,
    ) -> pd.DataFrame:
        """
        Загружает последние window_size строк по VLAN.
        Используется для online-detect.
        """

        query = text(f"""
            SELECT *
            FROM (
                SELECT *
                FROM {self.table_name}
                WHERE vlan_id = :vlan_id
                ORDER BY timestamp DESC
                LIMIT :window_size
            ) AS sub
            ORDER BY timestamp
        """)

        params = {"vlan_id": vlan_id, "window_size": window_size}
        df = pd.read_sql(query, self.engine, params=params)
        return df

    def insert_anomaly_result(
            self,
            *,
            timestamp,
            vlan_id: int,
            anomaly_score: float,
            is_anomaly: bool,
    ) -> None:
        sql = """
        INSERT INTO anomaly_results (
            timestamp, vlan_id, anomaly_score, is_anomaly
        ) VALUES (
            :timestamp,
            :vlan_id,
            :anomaly_score,
            :is_anomaly
        )   
        """
        with self.engine.begin() as conn:
            conn.execute(
                text(sql),
                {
                    "timestamp": timestamp,
                    "vlan_id": int(vlan_id),
                    "anomaly_score": float(anomaly_score),
                    "is_anomaly": bool(is_anomaly),
                },
            )
    def load_data_between(
        self,
        vlan_id: int,
        start_time,
        end_time,
    ) -> pd.DataFrame:
        """
        Загружает данные по VLAN в заданном интервале времени.
        Удобно для тестов и экспериментов.
        """

        query = text(f"""
            SELECT *
            FROM {self.table_name}
            WHERE vlan_id = :vlan_id
              AND timestamp >= :start_time
              AND timestamp <= :end_time
            ORDER BY timestamp
        """)

        params = {
            "vlan_id": vlan_id,
            "start_time": start_time,
            "end_time": end_time,
        }

        df = pd.read_sql(query, self.engine, params=params)
        return df