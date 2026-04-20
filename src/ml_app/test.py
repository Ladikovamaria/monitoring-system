from src.ml_app.db_reader import MetricsDBReader

DB_URL = "postgresql+psycopg2://monitsys_user:12345@localhost:5432/monitsys"
reader = MetricsDBReader(DB_URL, "features")

print("before get_available_vlans")
print(reader.get_available_vlans())
print("after get_available_vlans")