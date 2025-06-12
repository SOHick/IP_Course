import socket
import time
import signal
import sys
import dns.message
import dns.query
import dns.rrset
import dns.rdatatype
import dns.rdataclass
from DNS_Server_prod.DNS_v2.DNSCashe import *
logger = logging.getLogger(__name__)

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

    def cleanup_loop(self):
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
        self.sock.bind(('127.0.0.1', self.port))

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
