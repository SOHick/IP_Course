import pickle
import json
from datetime import datetime


def datetime_converter(o):
    if isinstance(o, datetime):
        return o.isoformat()  # Конвертируем datetime в строку ISO формата


# Загрузка данных из pickle
with open('dns_cache.pkl', 'rb') as f:
    cache_data = pickle.load(f)

# Конвертация в JSON с обработкой datetime
json_data = json.dumps(cache_data, default=datetime_converter, indent=2)

print("JSON представление кэша:")
print(json_data)

# Для сохранения в файл:
with open('dns_cache.json', 'w') as f:
    f.write(json_data)
