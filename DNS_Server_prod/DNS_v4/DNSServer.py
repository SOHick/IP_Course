import socket
import time
import signal
import dns.message
import dns.query
import dns.rrset
import dns.rdatatype
import dns.rdataclass
import dns.flags

from DNSCache import *
logger = logging.getLogger(__name__)



class DNSServer:
    def __init__(self, port=53, upstream_dns='8.8.8.8'):
        self.port = port
        self.upstream_dns = upstream_dns
        self.cache = DNSCache()
        self.running = False
        self.sock = None

        # Обработчики сигналов
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        """Обработчик сигналов для корректного завершения"""
        logging.info(f"Received signal {signum}, shutting down gracefully...")
        self.stop()

    def is_internet_available(self, timeout=3):
        """Проверяет доступность интернета"""
        try:
            socket.create_connection((self.upstream_dns, 53), timeout=timeout)
            return True
        except (socket.timeout, ConnectionError) as e3:
            logging.warning(f"Internet check failed: {e3}")
            return False
        except Exception as e4:
            logging.error(f"Unexpected internet check error: {e4}")
            return False

    def handle_request(self, data, addr):
        """Обрабатывает DNS-запрос"""
        try:
            request = dns.message.from_wire(data)
            if not request.question:
                logging.warning("Received empty DNS query")
                return

            qname = request.question[0].name.to_text()
            qtype = request.question[0].rdtype
            logging.info(f"Query from {addr[0]}:{addr[1]} for {qname} ({dns.rdatatype.to_text(qtype)})")

            response = None

            # 1. Пытаемся получить ответ из кеша
            cached_records = self.cache.get_record(qname, qtype)
            if cached_records:
                try:
                    response = dns.message.make_response(request)
                    cache_key = (qname.rstrip('.').lower(), dns.rdatatype.to_text(qtype))
                    expiry = self.cache.cache[cache_key][0]
                    ttl = max(1, int((expiry - datetime.now()).total_seconds()))

                    rrset = dns.rrset.from_text(
                        qname,
                        ttl,
                        'IN',
                        dns.rdatatype.to_text(qtype),
                        *cached_records
                    )
                    response.answer.append(rrset)
                    response.flags |= dns.flags.AA
                    logging.info(f"Serving from cache: {qname}")
                except Exception as e5:
                    logging.error(f"Cache response creation failed: {e5}")
                    response = dns.message.make_response(request)
                    response.set_rcode(dns.rcode.SERVFAIL)

            # 2. Если в кеше нет и есть интернет - запрашиваем у upstream
            elif self.is_internet_available():
                try:
                    logging.info(f"Forwarding query for {qname} to {self.upstream_dns}")
                    response = dns.query.udp(request, self.upstream_dns, timeout=3)

                    if response.answer:
                        for rrset in response.answer:
                            self.cache.add_record(rrset)
                except (dns.exception.Timeout, socket.timeout):
                    logging.warning(f"Upstream DNS timeout for {qname}")
                    response = dns.message.make_response(request)
                    response.set_rcode(dns.rcode.SERVFAIL)
                except ConnectionResetError:
                    logging.warning("Connection reset by peer (internet may be down)")
                    response = dns.message.make_response(request)
                    response.set_rcode(dns.rcode.REFUSED)
                except Exception as e6:
                    logging.error(f"Upstream query failed for {qname}: {e6}")
                    response = dns.message.make_response(request)
                    response.set_rcode(dns.rcode.SERVFAIL)

            # 3. Если интернета нет и в кеше нет ответа
            else:
                logging.warning(f"No internet and no cache for {qname}")
                response = dns.message.make_response(request)
                response.set_rcode(dns.rcode.REFUSED)

            # Отправляем ответ клиенту (с защитой от ошибок отправки)
            try:
                if response and self.sock:
                    self.sock.sendto(response.to_wire(), addr)
            except ConnectionResetError:
                logging.warning("Client connection reset during response")
            except Exception as e7:
                logging.error(f"Failed to send response to {addr}: {e7}")

        except Exception as e8:
            logging.error(f"Request handling error: {e8}")

    def start(self):
        """Запускает DNS-сервер"""
        try:
            self.cache.load_from_file()
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind(('127.0.0.1', self.port))
            self.sock.settimeout(1)  # Таймаут для проверки флага running
            self.running = True

            # Поток для периодической очистки кеша
            def cleanup_thread():
                while self.running:
                    time.sleep(60)
                    try:
                        self.cache.cleanup()
                        self.cache.save_to_file()
                    except Exception as e9:
                        logging.error(f"Cache maintenance error: {e9}")

            threading.Thread(target=cleanup_thread, daemon=True).start()
            logging.info(f"DNS server started on port {self.port}")

            # Основной цикл обработки запросов
            while self.running:
                try:
                    data, addr = self.sock.recvfrom(512)
                    threading.Thread(
                        target=self.handle_request,
                        args=(data, addr),
                        daemon=True
                    ).start()
                except socket.timeout:
                    continue  # Нормальная ситуация для проверки флага running
                except Exception as e10:
                    if self.running:  # Логируем только если это не запланированное закрытие
                        logging.error(f"Socket error: {e10}")
                    break

        except Exception as e11:
            logging.critical(f"Server startup failed: {e11}")
            raise
        finally:
            self.stop()

    def stop(self):
        """Останавливает сервер"""
        if not self.running:
            return

        self.running = False
        logging.info("Shutting down server...")

        try:
            if self.sock:
                self.sock.close()
        except Exception as e12:
            logging.error(f"Socket close error: {e12}")

        try:
            self.cache.save_to_file()
        except Exception as e13:
            logging.error(f"Cache save on shutdown failed: {e13}")

        logging.info("DNS server stopped gracefully")