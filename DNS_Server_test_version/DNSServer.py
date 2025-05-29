import time
from DNSResolver import *
from DNSProtocol import *

logger = logging.getLogger(__name__)

class DNSServer:
    """DNS сервер с кэшированием"""
    __slots__ = ['_port', '_cache', '_resolver', '_running', '_cleanup_thread']

    def __init__(self, port: int = 1025):
        self._port = port
        self._cache = DNSCache()
        self._resolver = DNSResolver(self._cache)
        self._running = False
        self._cleanup_thread = None

    def start(self) -> None:
        """Запускает DNS сервер"""
        self._running = True
        self._cache.load()

        # Запускаем очистку кэша в фоне
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()

        # Основной цикл сервера
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('0.0.0.0', self._port))
            logger.info(f"DNS сервер запущен на порту {self._port}")

            while self._running:
                try:
                    data, addr = sock.recvfrom(512)
                    threading.Thread(target=self._handle, args=(sock, data, addr)).start()
                except socket.error as e:
                    logger.error(f"Ошибка сокета: {e}")
                except Exception as e:
                    logger.error(f"Неожиданная ошибка: {e}")

    def stop(self) -> None:
        """Останавливает сервер"""
        self._running = False
        self._cache.save()
        if self._cleanup_thread:
            self._cleanup_thread.join()

    def _handle(self, sock: socket.socket, data: bytes, addr: Tuple[str, int]) -> None:
        """Обрабатывает DNS запрос"""
        print("dsfsd")
        try:
            query = DNSProtocol.parse_query(data)

            # Проверка кэша для A запросов
            if query['qtype'] == b'\x00\x01':
                cached = self._cache.get_record(query['qname'])
                if cached:
                    answer = DNSProtocol.build_a_record(query['qname'], cached, 60)
                    sock.sendto(DNSProtocol.build_response(query, [answer], [], []), addr)
                    return

            # Рекурсивное разрешение
            records = self._resolver.resolve(query['qname'], query['qtype'])

            # Формируем ответ
            answers = []
            authority = []
            additional = []

            for r in records:
                if r['type'] == 'A' and r.get('name', '').lower() == query['qname'].lower():
                    answers.append(DNSProtocol.build_a_record(r.get('name', query['qname']),
                                                              r['ip'], r['ttl']))
                elif r['type'] == 'NS':
                    authority.append(DNSProtocol.build_ns_record(r.get('name', query['qname']),
                                                                 r['name'], r['ttl']))
                elif r['type'] == 'A':
                    additional.append(DNSProtocol.build_a_record(r['name'], r['ip'], r['ttl']))

            sock.sendto(DNSProtocol.build_response(query, answers, authority, additional), addr)

        except ValueError as e:
            logger.error(f"Ошибка запроса: {e}")
            # Отправляем ошибку SERVFAIL
            response = data[:2] + b'\x81\x83' + data[4:6] + b'\x00\x00\x00\x00\x00\x00'
            sock.sendto(response, addr)
        except Exception as e:
            logger.error(f"Ошибка обработки запроса: {e}")

    def _cleanup_loop(self) -> None:
        """Цикл очистки просроченных записей"""
        while self._running:
            time.sleep(60)
            self._cache.cleanup()