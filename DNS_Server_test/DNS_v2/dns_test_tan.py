import socket
import threading
import time
import pickle
import logging
from datetime import datetime, timedelta
import signal
import sys
import dns.message
import dns.query
import dns.rrset
import dns.rdatatype
import dns.rdataclass
import dns.flags

# Настройка логгирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dns_server.log'),
        logging.StreamHandler()
    ]
)


class DNSCache:
    def __init__(self):
        self.domain_to_ip = {}  # {domain: {ip: (expiry_time, record_type)}}
        self.ip_to_domain = {}  # {ip: {domain: (expiry_time, record_type)}}
        self.domain_to_ns = {}  # {domain: {ns: (expiry_time)}}
        self.lock = threading.Lock()

    def add_record(self, rrset):
        """Добавляет DNS-запись в кэш из RRset"""
        with self.lock:
            if not isinstance(rrset, dns.rrset.RRset):
                logging.warning(f"Invalid RRset type: {type(rrset)}")
                return

            try:
                # Общее время жизни для всех записей в RRset
                expiry_time = datetime.now() + timedelta(seconds=rrset.ttl)
                record_type = dns.rdatatype.to_text(rrset.rdtype)

                # Обрабатываем все записи в RRset
                for rr in rrset:
                    try:
                        # A и AAAA записи (домен -> IP)
                        if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                            domain = rrset.name.to_text().rstrip('.').lower()
                            ip = rr.address

                            # Добавляем в domain_to_ip
                            if domain not in self.domain_to_ip:
                                self.domain_to_ip[domain] = {}
                            self.domain_to_ip[domain][ip] = (expiry_time, record_type)

                            # Добавляем в ip_to_domain
                            if ip not in self.ip_to_domain:
                                self.ip_to_domain[ip] = {}
                            self.ip_to_domain[ip][domain] = (expiry_time, record_type)

                        # NS записи (домен -> nameserver)
                        elif rrset.rdtype == dns.rdatatype.NS:
                            domain = rrset.name.to_text().rstrip('.').lower()
                            ns = rr.target.to_text().rstrip('.').lower()

                            if domain not in self.domain_to_ns:
                                self.domain_to_ns[domain] = {}
                            self.domain_to_ns[domain][ns] = expiry_time

                        # PTR записи (IP -> домен)
                        elif rrset.rdtype == dns.rdatatype.PTR:
                            ip = rrset.name.to_text().rstrip('.').lower()
                            domain = rr.target.to_text().rstrip('.').lower()

                            # Добавляем в ip_to_domain
                            if ip not in self.ip_to_domain:
                                self.ip_to_domain[ip] = {}
                            self.ip_to_domain[ip][domain] = (expiry_time, record_type)

                            # Добавляем в domain_to_ip
                            if domain not in self.domain_to_ip:
                                self.domain_to_ip[domain] = {}
                            self.domain_to_ip[domain][ip] = (expiry_time, record_type)

                    except AttributeError as e:
                        logging.error(f"Failed to process RR {rr}: {e}")
                        continue

                logging.debug(f"Cached {record_type} record: {rrset.to_text()}")

            except Exception as e:
                logging.error(f"Error processing RRset {rrset}: {e}")

    def get_a_record(self, domain):
        """Получает A запись для домена"""
        domain = domain.lower()
        with self.lock:
            if domain in self.domain_to_ip:
                ips = {}
                for ip, (expiry, rtype) in self.domain_to_ip[domain].items():
                    if rtype in ('A', 'AAAA') and expiry > datetime.now():
                        ips[ip] = (expiry, rtype)
                return ips if ips else None
            return None

    def get_ptr_record(self, ip):
        """Получает PTR запись для IP"""
        ip = ip.lower()
        with self.lock:
            if ip in self.ip_to_domain:
                domains = {}
                for domain, (expiry, rtype) in self.ip_to_domain[ip].items():
                    if rtype == 'PTR' and expiry > datetime.now():
                        domains[domain] = expiry
                return domains if domains else None
            return None

    def get_ns_records(self, domain):
        """Получает NS записи для домена"""
        domain = domain.lower()
        with self.lock:
            if domain in self.domain_to_ns:
                nss = {}
                for ns, expiry in self.domain_to_ns[domain].items():
                    if expiry > datetime.now():
                        nss[ns] = expiry
                return nss if nss else None
            return None

    def cleanup(self):
        """Очищает просроченные записи"""
        with self.lock:
            now = datetime.now()

            # Очистка domain_to_ip
            for domain in list(self.domain_to_ip.keys()):
                ips = self.domain_to_ip[domain]
                for ip in list(ips.keys()):
                    if ips[ip][0] <= now:
                        del ips[ip]
                if not ips:
                    del self.domain_to_ip[domain]

            # Очистка ip_to_domain
            for ip in list(self.ip_to_domain.keys()):
                domains = self.ip_to_domain[ip]
                for domain in list(domains.keys()):
                    if domains[domain][0] <= now:
                        del domains[domain]
                if not domains:
                    del self.ip_to_domain[ip]

            # Очистка domain_to_ns
            for domain in list(self.domain_to_ns.keys()):
                nss = self.domain_to_ns[domain]
                for ns in list(nss.keys()):
                    if nss[ns] <= now:
                        del nss[ns]
                if not nss:
                    del self.domain_to_ns[domain]

    def save_to_file(self, filename='dns_cache.pkl'):
        """Сохраняет кэш в файл"""
        with self.lock:
            with open(filename, 'wb') as f:
                data = {
                    'domain_to_ip': self.domain_to_ip,
                    'ip_to_domain': self.ip_to_domain,
                    'domain_to_ns': self.domain_to_ns,
                    'timestamp': datetime.now()
                }
                pickle.dump(data, f)

    def load_from_file(self, filename='dns_cache.pkl'):
        """Загружает кэш из файла и удаляет просроченные записи"""
        try:
            with open(filename, 'rb') as f:
                data = pickle.load(f)
                self.domain_to_ip = data['domain_to_ip']
                self.ip_to_domain = data['ip_to_domain']
                self.domain_to_ns = data['domain_to_ns']
                load_time = data['timestamp']

                # Удаляем просроченные записи
                now = datetime.now()
                for cache in [self.domain_to_ip, self.ip_to_domain, self.domain_to_ns]:
                    for key in list(cache.keys()):
                        records = cache[key]
                        for record_key in list(records.keys()):
                            if isinstance(records[record_key], tuple):
                                expiry = records[record_key][0]
                            else:
                                expiry = records[record_key]

                            if expiry <= now:
                                del records[record_key]
                        if not records:
                            del cache[key]

                logging.info(f"Cache loaded from {filename}, expired records removed")
                return True
        except (FileNotFoundError, pickle.PickleError, KeyError) as e:
            logging.warning(f"Could not load cache: {e}")
            return False



class DNSServer:
    def __init__(self, port=53, upstream_dns='8.8.8.8'):
        self.port = port
        self.upstream_dns = upstream_dns
        self.cache = DNSCache()
        self.running = False
        self.cleanup_thread = None
        self.sock = None
        # Регистрируем обработчик сигнала
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        """Обработчик сигналов для корректного завершения"""
        logging.info(f"Received signal {signum}, shutting down...")
        self.stop()
        sys.exit(0)

    def cleanup_loop(self):  # Обратите внимание на маленькую 'c'
        """Периодически очищает кэш от просроченных записей"""
        while self.running:
            time.sleep(60)
            self.cache.cleanup()
            logging.debug("Cache cleanup performed")

    def handle_request(self, data, addr):
        """Обрабатывает DNS запрос"""
        try:
            request = dns.message.from_wire(data)
            logging.info(f"Received query from {addr[0]}:{addr[1]} for {request.question[0].name}")

            response = None

            # Проверяем кэш для каждого вопроса в запросе
            for question in request.question:
                qname = question.name.to_text()
                qtype = question.rdtype

                if qtype == dns.rdatatype.A:
                    cached = self.cache.get_a_record(qname)
                    if cached:
                        response = dns.message.make_response(request)
                        rrset = dns.rrset.RRSet.from_text(qname, 60, 'IN', 'A', *cached.keys())
                        response.answer.append(rrset)
                        logging.info(f"Serving from cache: {qname} -> {list(cached.keys())}")
                        break

                elif qtype == dns.rdatatype.PTR:
                    cached = self.cache.get_ptr_record(qname)
                    if cached:
                        response = dns.message.make_response(request)
                        rrset = dns.rrset.RRset.from_text(qname, 60, 'IN', 'PTR', *cached.keys())
                        response.answer.append(rrset)
                        logging.info(f"Serving from cache: {qname} -> {list(cached.keys())}")
                        break

            # Если в кэше нет ответа, делаем рекурсивный запрос
            if not response:
                try:
                    logging.info(f"Querying upstream DNS {self.upstream_dns} for {request.question[0].name}")
                    response = dns.query.udp(request, self.upstream_dns)

                    # Добавляем все записи в кэш
                    for section in [response.answer, response.authority, response.additional]:
                        for rrset in section:
                            self.cache.add_record(rrset)

                    logging.info(f"Received response from upstream for {request.question[0].name}")
                except Exception as e:
                    logging.error(f"Failed to query upstream DNS: {e}")
                    response = dns.message.make_response(request)
                    response.set_rcode(dns.rcode.SERVFAIL)

            # Отправляем ответ клиенту
            self.sock.sendto(response.to_wire(), addr)
            logging.info(f"Sent response to {addr[0]}:{addr[1]}")

        except Exception as e:
            logging.error(f"Error handling request: {e}")
            try:
                response = dns.message.make_response(dns.message.from_wire(data))
                response.set_rcode(dns.rcode.SERVFAIL)
                self.sock.sendto(response.to_wire(), addr)
            except:
                pass

    def stop(self):
        """Останавливает сервер и сохраняет кэш"""
        self.running = False
        if self.sock:
            # Закрываем сокет, чтобы выйти из блокирующего recvfrom
            self.sock.close()
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=1)
        self.cache.save_to_file()
        logging.info("DNS server stopped, cache saved")

    def start(self):
        """Запускает DNS сервер"""
        self.cache.load_from_file()

        # Создаем UDP сокет
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('192.168.96.1', self.port))

        self.running = True
        logging.info(f"DNS server started on port {self.port}")

        # Запускаем поток для очистки кэша
        self.cleanup_thread = threading.Thread(target=self.cleanup_loop, daemon=True)
        self.cleanup_thread.start()

        # Основной цикл обработки запросов с таймаутом
        self.sock.settimeout(1)  # Таймаут 1 секунда для проверки флага running
        try:
            while self.running:
                try:
                    data, addr = self.sock.recvfrom(512)
                    threading.Thread(target=self.handle_request, args=(data, addr), daemon=True).start()
                except socket.timeout:
                    continue  # Просто продолжаем цикл если таймаут
                except socket.error as e:
                    if self.running:  # Логируем только если это не запланированное закрытие
                        logging.error(f"Socket error: {e}")
                    break
        except KeyboardInterrupt:
            pass  # Обработка через signal_handler
        finally:
            self.stop()


if __name__ == '__main__':
    server = DNSServer(port=53)
    server.start()