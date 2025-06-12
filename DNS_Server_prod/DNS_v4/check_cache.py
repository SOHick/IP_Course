import pickle
import json
from datetime import datetime
import dns.rdatatype


def cache_to_json(cache_file='dns_cache.pkl', output_file='dns_cache.json'):
    """
    Конвертирует данные из бинарного кеша в читаемый JSON-формат
    """
    try:
        # Загружаем данные из кеша
        with open(cache_file, 'rb') as f:
            cache_data = pickle.load(f)

        # Подготовка данных для JSON
        result = {
            'timestamp': datetime.now().isoformat(),
            'cache_source': cache_file,
            'records': []
        }

        # Обрабатываем каждую запись в кеше
        for (qname, qtype), (expiry, records) in cache_data.items():
            # Преобразуем тип записи в читаемый формат
            try:
                qtype_name = dns.rdatatype.to_text(int(qtype)) if qtype.isdigit() else qtype
            except:
                qtype_name = str(qtype)

            record_data = {
                'domain': qname,
                'type': qtype_name,
                'expires': expiry.isoformat(),
                'ttl_remaining': max(0, int((expiry - datetime.now()).total_seconds())),
                'records': records
            }
            result['records'].append(record_data)

        # Сортируем записи по домену
        result['records'].sort(key=lambda x: x['domain'])

        # Сохраняем в JSON
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        print(f"Successfully converted cache to {output_file}")
        return True

    except FileNotFoundError:
        print(f"Error: Cache file {cache_file} not found")
        return False
    except Exception as e:
        print(f"Error converting cache: {str(e)}")
        return False


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Convert DNS cache to JSON')
    parser.add_argument('--input', default='dns_cache.pkl', help='Input cache file (pickle format)')
    parser.add_argument('--output', default='dns_cache.json', help='Output JSON file')

    args = parser.parse_args()

    if cache_to_json(args.input, args.output):
        print(f"Cache data saved to {args.output}")
    else:
        print("Failed to convert cache data")