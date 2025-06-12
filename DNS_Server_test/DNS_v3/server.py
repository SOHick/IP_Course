import pickle
import socket
import struct
import time
import logging
import argparse
import sys
import signal
from collections import defaultdict

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dns_proxy.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Константы DNS
QTYPE_A = 1
QTYPE_NS = 2
QTYPE_PTR = 12
QTYPE_AAAA = 28


class DNSCache:
    def __init__(self):
        self.records = defaultdict(list)

    def add_record(self, name, rtype, data, ttl):
        """Добавляет запись в кэш"""
        self.records[(name, rtype)].append({
            'data': data,
            'expire': time.time() + ttl
        })

    def get_records(self, name, rtype):
        """Возвращает валидные записи для указанного имени и типа"""
        current_time = time.time()
        return [
            r for r in self.records.get((name, rtype), [])
            if r['expire'] > current_time
        ]

    def clean_expired(self):
        """Очищает просроченные записи"""
        current_time = time.time()
        removed = 0

        for key in list(self.records.keys()):
            self.records[key] = [
                r for r in self.records[key]
                if r['expire'] > current_time
            ]
            if not self.records[key]:
                del self.records[key]
                removed += 1

        if removed > 0:
            logger.info(f"Removed {removed} expired records")

        return removed

    def save_to_file(self, filename):
        """Сохраняет кэш в файл"""
        try:
            with open(filename, 'wb') as f:
                # Сохраняем как обычный словарь
                pickle.dump(dict(self.records), f)
            logger.info(f"Cache saved to {filename}")
            return True
        except Exception as e:
            logger.error(f"Failed to save cache: {e}")
            return False

    def load_from_file(self, filename):
        """Загружает кэш из файла"""
        try:
            with open(filename, 'rb') as f:
                data = pickle.load(f)
                if not isinstance(data, dict):
                    raise ValueError("Invalid cache format")

                self.records.clear()
                for key, records in data.items():
                    if isinstance(records, list):
                        self.records[key].extend(records)

            logger.info(f"Cache loaded from {filename}")
            self.clean_expired()
            return True
        except FileNotFoundError:
            logger.info("No cache file found, starting fresh")
            return True
        except Exception as e:
            logger.error(f"Failed to load cache: {e}")
            return False


def decode_name(data, offset):
    """Декодирует доменное имя из DNS-пакета"""
    name = []
    original_offset = offset
    processed_pointers = set()

    while True:
        if offset >= len(data):
            raise ValueError("Offset out of range")

        length = data[offset]

        if (length & 0xc0) == 0xc0:  # Компрессия
            if offset + 1 >= len(data):
                raise ValueError("Invalid compression pointer")

            pointer = struct.unpack('!H', data[offset:offset + 2])[0] & 0x3fff
            if pointer in processed_pointers:
                raise ValueError("Compression loop detected")

            processed_pointers.add(pointer)
            part, _ = decode_name(data, pointer)
            name.append(part)
            return '.'.join(name), offset + 2

        elif length > 0:  # Обычная метка
            if offset + 1 + length > len(data):
                raise ValueError("Label exceeds packet length")

            name.append(data[offset + 1:offset + 1 + length].decode('ascii',
                                                                    'replace'))
            offset += 1 + length
        else:  # Конец имени
            return '.'.join(name), offset + 1


def encode_name(name):
    """Кодирует доменное имя для DNS-пакета"""
    encoded = bytearray()
    for part in name.split('.'):
        encoded.append(len(part))
        encoded.extend(part.encode('ascii', 'replace'))
    encoded.append(0)
    return bytes(encoded)


def parse_dns_query(data):
    """Разбирает DNS-запрос"""
    try:
        if len(data) < 12:
            raise ValueError("Packet too short")

        header = struct.unpack('!6H', data[:12])
        query_id = header[0]
        qdcount = header[2]

        questions = []
        offset = 12

        for _ in range(qdcount):
            if offset >= len(data):
                raise ValueError("Question section truncated")

            name, offset = decode_name(data, offset)

            if offset + 4 > len(data):
                raise ValueError("Question type/class truncated")

            qtype, qclass = struct.unpack('!2H', data[offset:offset + 4])
            questions.append({
                'name': name,
                'type': qtype,
                'class': qclass
            })
            offset += 4

        return {
            'id': query_id,
            'questions': questions,
            'header': header
        }
    except Exception as e:
        logger.error(f"Failed to parse query: {e}")
        return None


def build_dns_response(query, answers):
    """Строит DNS-ответ"""
    try:
        if not query or not answers:
            raise ValueError("Invalid input")

        question = query['questions'][0]

        # Формируем заголовок
        flags = 0x8180  # QR=1, RD=1, RA=1
        header = struct.pack('!6H',
                             query['id'],
                             flags,
                             1,  # QDCOUNT
                             len(answers),  # ANCOUNT
                             0,  # NSCOUNT
                             0  # ARCOUNT
                             )

        # Кодируем вопрос
        encoded_question = encode_name(question['name'])
        encoded_question += struct.pack('!2H', question['type'],
                                        question['class'])

        # Формируем ответ
        response = bytearray()
        response.extend(header)
        response.extend(encoded_question)

        for answer in answers:
            encoded_name = encode_name(answer['name'])
            response.extend(encoded_name)

            response.extend(struct.pack('!2HIH',
                                        answer['type'],
                                        1,  # CLASS IN
                                        answer['ttl'],
                                        len(answer['data'])
                                        ))

            response.extend(answer['data'])

        return bytes(response)
    except Exception as e:
        logger.error(f"Failed to build response: {e}")
        return None


def forward_query(query_data, upstream_dns, upstream_port):
    """Отправляет запрос к вышестоящему DNS-серверу"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2.0)
            sock.sendto(query_data, (upstream_dns, upstream_port))
            response, _ = sock.recvfrom(512)
            return response
    except socket.timeout:
        logger.warning("Upstream DNS timeout")
        return None
    except Exception as e:
        logger.error(f"Upstream query failed: {e}")
        return None


def parse_dns_response(response, query):
    """Разбирает DNS-ответ и добавляет записи в кэш"""
    if not response or len(response) < 12:
        return None

    try:
        header = struct.unpack('!6H', response[:12])
        ancount = header[3]
        nscount = header[4]
        arcount = header[5]

        offset = 12
        # Пропускаем вопросы
        for _ in range(header[2]):
            _, offset = decode_name(response, offset)
            offset += 4

        records = []

        # Обрабатываем ответы
        for _ in range(ancount + nscount + arcount):
            if offset >= len(response):
                break

            name, offset = decode_name(response, offset)

            if offset + 10 > len(response):
                break

            rtype, rclass, ttl, rdlength = struct.unpack('!2HIH', response[
                                                                  offset:offset + 10])
            offset += 10

            if offset + rdlength > len(response):
                break

            rdata = response[offset:offset + rdlength]
            offset += rdlength

            if rclass == 1:  # Только записи класса IN
                records.append({
                    'name': name,
                    'type': rtype,
                    'data': rdata,
                    'ttl': ttl
                })

        return records
    except Exception as e:
        logger.error(f"Failed to parse response: {e}")
        return None


def process_dns_query(data, cache, upstream_dns, upstream_port):
    """Обрабатывает DNS-запрос"""
    try:
        query = parse_dns_query(data)
        if not query or not query['questions']:
            return None

        question = query['questions'][0]
        logger.info(
            f"Processing query: {question['name']} type {question['type']}")

        # Проверяем кэш
        cached_records = cache.get_records(question['name'], question['type'])
        if cached_records:
            logger.info(f"Using cached response for {question['name']}")
            answers = [{
                'name': question['name'],
                'type': question['type'],
                'ttl': int(record['expire'] - time.time()),
                'data': record['data']
            } for record in cached_records]
            return build_dns_response(query, answers)

        # Запрашиваем у вышестоящего сервера
        logger.info(f"Forwarding query for {question['name']}")
        response = forward_query(data, upstream_dns, upstream_port)
        if not response:
            return None

        # Добавляем записи в кэш
        records = parse_dns_response(response, query)
        if records:
            for record in records:
                if record['type'] in (
                QTYPE_A, QTYPE_AAAA, QTYPE_NS, QTYPE_PTR):
                    cache.add_record(record['name'], record['type'],
                                     record['data'], record['ttl'])

        return response

    except Exception as e:
        logger.error(f"Query processing failed: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(description='DNS caching proxy server')
    parser.add_argument('--upstream-dns', default='8.8.8.8',
                        help='Upstream DNS server')
    parser.add_argument('--upstream-port', type=int, default=53,
                        help='Upstream DNS port')
    parser.add_argument('--listen-port', type=int, default=53,
                        help='Local port to listen on')
    parser.add_argument('--listen-addr', default='192.168.96.1',
                        help='Local address to listen on')
    parser.add_argument('--cache-ttl', type=int, default=300,
                        help='Cache TTL in seconds')
    parser.add_argument('--backup-file', default='dns_cache.pkl',
                        help='Cache backup filename')
    args = parser.parse_args()

    cache = DNSCache()

    # Загрузка кэша
    if not cache.load_from_file(args.backup_file):
        logger.warning("Starting with empty cache due to load error")

    # Настройка сокета
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.listen_addr, args.listen_port))
    sock.settimeout(1.0)

    logger.info(f"DNS proxy started on {args.listen_addr}:{args.listen_port}")
    logger.info(
        f"Using upstream DNS: {args.upstream_dns}:{args.upstream_port}")

    def shutdown(signum, frame):
        logger.info("Shutting down server...")
        cache.save_to_file(args.backup_file)
        sock.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    last_cleanup = time.time()

    try:
        while True:
            try:
                # Принимаем запрос
                data, addr = sock.recvfrom(512)
                logger.debug(f"Received query from {addr}")

                # Обрабатываем запрос
                response = process_dns_query(
                    data,
                    cache,
                    args.upstream_dns,
                    args.upstream_port
                )

                # Отправляем ответ
                if response:
                    sock.sendto(response, addr)

                # Периодическая очистка кэша
                if time.time() - last_cleanup > 60:
                    cache.clean_expired()
                    last_cleanup = time.time()

            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                continue

    except Exception as e:
        logger.critical(f"Fatal error: {e}")
    finally:
        cache.save_to_file(args.backup_file)
        sock.close()
        logger.info("Server stopped")


if __name__ == '__main__':
    main()