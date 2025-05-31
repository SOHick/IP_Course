from DNS_Server_test.DNS_v1.DNSCache import *
from DNS_Server_test.DNS_v1.DNSProtocol import *



logger = logging.getLogger(__name__)

class DNSResolver:
    """Рекурсивный DNS резолвер с кэшированием"""
    __slots__ = ['_cache', '_root_servers', '_timeout']

    def __init__(self, cache: DNSCache):
        self._cache = cache
        self._root_servers = [
            '127.0.0.1'
        ]
        self._timeout = 3

    def resolve(self, qname: str, qtype: bytes) -> List[Dict]:
        """Рекурсивно разрешает DNS запрос"""
        qname = qname.lower()

        # Проверка кэша для A запросов
        if qtype == b'\x00\x01':
            cached = self._cache.get_record(qname)
            if cached:
                return [{'type': 'A', 'name': qname, 'ip': cached, 'ttl': 60}]

        # Рекурсивное разрешение
        try:
            records = self._resolve(qname, qtype, self._root_servers)

            # Кэшируем результаты
            for r in records:
                if r['type'] == 'A':
                    self._cache.add_record(r.get('name', qname), r['ip'], r['ttl'])
                elif r['type'] == 'NS':
                    self._cache.add_ns_record(r.get('name', qname), r['name'], r['ttl'])

            return records
        except Exception as e:
            logger.error(f"Ошибка разрешения {qname}: {e}")
            raise

    def _resolve(self, qname: str, qtype: bytes, servers: List[str]) -> List[Dict]:
        """Рекурсивное разрешение через указанные серверы"""
        for server in servers:
            try:
                response = self._query(qname, qtype, server)
                records = DNSProtocol.parse_response(response)

                # Ищем ответы
                answers = [r for r in records
                           if r['type'] in ('A', 'AAAA') and r.get('name', '').lower() == qname]
                if answers:
                    return records

                # Ищем NS записи и соответствующие A записи
                ns_records = [r for r in records if r['type'] == 'NS']
                additional_a = [r for r in records if r['type'] in ('A', 'AAAA')]

                if ns_records:
                    # Получаем IP для NS серверов
                    ns_servers = []
                    for ns in ns_records:
                        ns_name = ns['name']
                        # Проверяем Additional секцию
                        for a in additional_a:
                            if a.get('name', '').lower() == ns_name.lower():
                                ns_servers.append(a['ip'])

                        # Проверяем кэш
                        if not ns_servers:
                            cached_ip = self._cache.get_record(ns_name)
                            if cached_ip:
                                ns_servers.append(cached_ip)

                    if ns_servers:
                        return self._resolve(qname, qtype, ns_servers)

                # Проверяем CNAME
                cname_records = [r for r in records
                                 if r['type'] == 'CNAME' and r.get('name', '').lower() == qname]
                if cname_records:
                    return self._resolve(cname_records[0]['name'], qtype, self._root_servers)

            except (socket.timeout, socket.error) as e:
                logger.debug(f"Сервер {server} не ответил: {e}")
                continue

        raise ValueError(f"Не удалось разрешить {qname}")

    def _query(self, qname: str, qtype: bytes, server: str) -> bytes:
        """Отправляет DNS запрос на указанный сервер"""
        # Строим запрос
        query = b'\x12\x34'  # Transaction ID
        query += b'\x01\x00'  # Flags: Recursion Desired
        query += b'\x00\x01'  # Questions
        query += b'\x00\x00'  # Answer RRs
        query += b'\x00\x00'  # Authority RRs
        query += b'\x00\x00'  # Additional RRs

        # Вопрос
        for label in qname.split('.'):
            query += len(label).to_bytes(1, 'big') + label.encode('ascii')
        query += b'\x00' + qtype + b'\x00\x01'  # QTYPE and QCLASS

        # Отправляем запрос
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(self._timeout)
            s.sendto(query, (server, 1025))
            response, _ = s.recvfrom(512)
            return response