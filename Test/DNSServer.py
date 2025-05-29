import socket
import struct
from DNSCashe import *
logger = logging.getLogger(__name__)

class DNSServer:
    def __init__(self, port=1025):
        self.port = port
        self.cache = DNSCache()
        self.running = False
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(1)

        # Корневые DNS серверы
        self.root_servers = [
            '198.41.0.4', '199.9.14.201', '192.33.4.12',
            '199.7.91.13', '192.203.230.10', '192.5.5.241',
            '192.112.36.4', '198.97.190.53', '192.36.148.17',
            '192.58.128.30', '193.0.14.129', '199.7.83.42',
            '202.12.27.33'
        ]

    def start(self):
        """Запускает DNS сервер"""
        if not self.cache.load():
            logger.info("Cache is empty, starting with fresh cache")

        try:
            self.socket.bind(('127.0.0.1', self.port))
            self.running = True
            logger.info(f"DNS server is running on 127.0.0.1:{self.port}...")

            # Поток для очистки кэша
            threading.Thread(target=self.cleanup_loop, daemon=True).start()

            while self.running:
                try:
                    data, addr = self.socket.recvfrom(512)
                    threading.Thread(target=self.handle_request, args=(data, addr)).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Error receiving data: {e}")
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            self.stop()

    def cleanup_loop(self):
        """Цикл очистки кэша"""
        while self.running:
            time.sleep(60)
            self.cache.cleanup()
            logger.debug("Cache cleanup performed")

    def stop(self):
        """Останавливает сервер"""
        if self.running:
            self.running = False
            self.cache.save()
            self.socket.close()
            logger.info("DNS server stopped")

    def handle_request(self, data: bytes, addr: Tuple[str, int]):
        """Обрабатывает DNS запрос"""
        try:
            if len(data) < 12:
                return

            # Парсим запрос
            tid = data[:2]
            domain, qtype = self.parse_question(data[12:])

            if not domain:
                return

            logger.info(f"Query from {addr}: {domain} {qtype}")

            # Проверяем кэш
            cached = self.cache.get_record(domain, qtype)
            if cached:
                logger.info(f"Cache hit for {domain} {qtype}")
                self.socket.sendto(cached, addr)
                return

            # Рекурсивный запрос
            response = self.recursive_resolve(domain, qtype)
            if response:
                self.parse_and_cache_response(response)
                answer = self.extract_answer(response, qtype)
                if answer:
                    self.socket.sendto(answer, addr)
        except Exception as e:
            logger.error(f"Error handling request: {e}")

    def recursive_resolve(self, domain: str, qtype: str, depth=0) -> Optional[bytes]:
        """Рекурсивно разрешает DNS запрос"""
        if depth > 10:
            logger.warning(f"Max recursion depth reached for {domain}")
            return None

        # Пробуем корневые серверы по очереди
        for ns in self.root_servers:
            try:
                response = self.query_dns_server(domain, qtype, ns)
                if response:
                    return response
            except Exception as e:
                logger.warning(f"Query to {ns} failed: {e}")

        return None

    def query_dns_server(self, domain: str, qtype: str, server: str) -> Optional[bytes]:
        """Запрашивает DNS сервер"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                query = self.build_query(domain, qtype)
                s.sendto(query, (server, 53))
                response, _ = s.recvfrom(512)
                return response
        except Exception as e:
            logger.warning(f"Query to {server} failed: {e}")
            return None

    def build_query(self, domain: str, qtype: str) -> bytes:
        """Строит DNS запрос"""
        tid = os.urandom(2)
        flags = b'\x01\x00'  # Standard query, recursion desired
        qdcount = b'\x00\x01'  # One question
        counts = b'\x00\x00' * 3  # AN, NS, AR counts

        header = tid + flags + qdcount + counts

        # Question section
        question = b''
        for part in domain.split('.'):
            question += bytes([len(part)]) + part.encode('ascii')
        question += b'\x00'  # End of domain

        # Query type and class
        if qtype == 'A':
            question += b'\x00\x01'  # Type A
        elif qtype == 'AAAA':
            question += b'\x00\x1c'  # Type AAAA
        elif qtype == 'NS':
            question += b'\x00\x02'  # Type NS
        question += b'\x00\x01'  # Class IN

        return header + question

    def parse_question(self, data: bytes) -> Tuple[Optional[str], Optional[str]]:
        """Парсит секцию вопроса"""
        try:
            domain = []
            offset = 0
            while True:
                length = data[offset]
                if length == 0:
                    break
                domain.append(data[offset + 1:offset + 1 + length].decode('ascii'))
                offset += 1 + length

            offset += 1  # Skip null byte
            qtype = data[offset:offset + 2]

            if qtype == b'\x00\x01':
                return '.'.join(domain), 'A'
            elif qtype == b'\x00\x1c':
                return '.'.join(domain), 'AAAA'
            elif qtype == b'\x00\x02':
                return '.'.join(domain), 'NS'
            else:
                return None, None
        except:
            return None, None

    def parse_and_cache_response(self, response: bytes):
        """Парсит ответ и сохраняет записи в кэш"""
        try:
            # Skip header (12 bytes) and question section
            pos = 12
            while response[pos] != 0:
                pos += 1
            pos += 5  # Skip null byte + QTYPE + QCLASS

            # Parse answers
            ancount = struct.unpack('!H', response[6:8])[0]
            for _ in range(ancount):
                pos, name, rtype, ttl, rdata = self.parse_rr(response, pos)
                if rtype and rdata:
                    self.cache.add_record(name, rtype, rdata, ttl)
                    logger.info(f"Cached record: {name} {ttl} IN {rtype} {rdata}")
        except Exception as e:
            logger.error(f"Error parsing response: {e}")

    def parse_rr(self, data: bytes, pos: int) -> Tuple[int, str, str, int, bytes]:
        """Парсит ресурсную запись"""
        try:
            # Parse name (may be compressed)
            name, pos = self.parse_name(data, pos)

            # Parse type, class, TTL and data length
            rtype, _, ttl, rdlength = struct.unpack('!HHIH', data[pos:pos + 10])
            pos += 10

            # Parse data
            if rtype == 1:  # A record
                rdata = data[pos:pos + 4]
                pos += 4
                return pos, name, 'A', ttl, rdata
            elif rtype == 28:  # AAAA record
                rdata = data[pos:pos + 16]
                pos += 16
                return pos, name, 'AAAA', ttl, rdata
            elif rtype == 2:  # NS record
                nsname, _ = self.parse_name(data, pos)
                pos += rdlength
                return pos, name, 'NS', ttl, nsname.encode('ascii')
            else:
                pos += rdlength
                return pos, None, None, None, None
        except Exception as e:
            logger.error(f"Error parsing RR: {e}")
            return pos, None, None, None, None

    def parse_name(self, data: bytes, pos: int) -> Tuple[str, int]:
        """Парсит доменное имя (с поддержкой компрессии)"""
        try:
            name = []
            while True:
                length = data[pos]
                if (length & 0xc0) == 0xc0:  # Compression pointer
                    pointer = struct.unpack('!H', data[pos:pos + 2])[0] & 0x3fff
                    part, _ = self.parse_name(data, pointer)
                    name.append(part)
                    pos += 2
                    break
                elif length == 0:
                    pos += 1
                    break
                else:
                    name.append(data[pos + 1:pos + 1 + length].decode('ascii'))
                    pos += 1 + length
            return '.'.join(name), pos
        except Exception as e:
            logger.error(f"Error parsing name: {e}")
            return None, pos

    def extract_answer(self, response: bytes, qtype: str) -> Optional[bytes]:
        """Извлекает ответ из DNS пакета"""
        try:
            # Build response header
            tid = response[:2]
            flags = b'\x81\x80'  # Response, recursion available, no error
            qdcount = b'\x00\x01'  # One question
            ancount = struct.pack('!H', len(self.get_answer_section(response, qtype)))
            counts = b'\x00\x00' * 2  # NS and AR counts
            header = tid + flags + qdcount + ancount + counts

            # Copy question section
            pos = 12
            while response[pos] != 0:
                pos += 1
            question = response[12:pos + 5]  # Include QTYPE and QCLASS

            # Build answer section
            answer = self.get_answer_section(response, qtype)

            return header + question + answer
        except Exception as e:
            logger.error(f"Error building response: {e}")
            return None

    def get_answer_section(self, response: bytes, qtype: str) -> bytes:
        """Возвращает секцию ответа"""
        answer = b''

        # Skip header and question section
        pos = 12
        while response[pos] != 0:
            pos += 1
        pos += 5  # Skip null byte + QTYPE + QCLASS

        # Parse answers
        ancount = struct.unpack('!H', response[6:8])[0]
        for _ in range(ancount):
            pos, name, rtype, ttl, rdata = self.parse_rr(response, pos)
            if rtype == qtype:
                answer += b'\xc0\x0c'  # Pointer to domain name in question
                if rtype == 'A':
                    answer += b'\x00\x01'  # Type A
                    answer += b'\x00\x01'  # Class IN
                    answer += struct.pack('!I', ttl)
                    answer += b'\x00\x04'  # Data length
                    answer += rdata
                elif rtype == 'AAAA':
                    answer += b'\x00\x1c'  # Type AAAA
                    answer += b'\x00\x01'  # Class IN
                    answer += struct.pack('!I', ttl)
                    answer += b'\x00\x10'  # Data length
                    answer += rdata
                elif rtype == 'NS':
                    answer += b'\x00\x02'  # Type NS
                    answer += b'\x00\x01'  # Class IN
                    answer += struct.pack('!I', ttl)
                    answer += struct.pack('!H', len(rdata))
                    answer += rdata

        return answer