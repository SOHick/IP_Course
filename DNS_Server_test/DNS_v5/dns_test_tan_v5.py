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
        self.cache = {}  # {(qname, qtype): (expiry_time, records)}
        self.lock = threading.Lock()

    def add_record(self, rrset):
        """Добавляет DNS-запись в кэш"""
        if not rrset:
            return

        with self.lock:
            try:
                qname = rrset.name.to_text().rstrip('.').lower()
                qtype = dns.rdatatype.to_text(rrset.rdtype)
                expiry = datetime.now() + timedelta(seconds=rrset.ttl)
                records = [rr.to_text() for rr in rrset]

                self.cache[(qname, qtype)] = (expiry, records)
                logging.debug(f"Cached: {qname} {qtype} -> {records}")
            except Exception as e:
                logging.error(f"Cache add error: {e}")

    def get_record(self, qname, qtype):
        """Получает запись из кэша"""
        qname = qname.rstrip('.').lower()
        qtype = dns.rdatatype.to_text(qtype)

        with self.lock:
            cached = self.cache.get((qname, qtype))
            if cached:
                expiry, records = cached
                if expiry > datetime.now():
                    return records
                else:
                    del self.cache[(qname, qtype)]
            return None

    def cleanup(self):
        """Очищает просроченные записи"""
        with self.lock:
            now = datetime.now()
            expired = [k for k, v in self.cache.items() if v[0] <= now]
            for key in expired:
                del self.cache[key]
            if expired:
                logging.debug(f"Cleaned {len(expired)} expired records")

    def save_to_file(self, filename='dns_cache.pkl'):
        """Сохраняет кэш в файл"""
        with self.lock:
            try:
                with open(filename, 'wb') as f:
                    pickle.dump(self.cache, f)
                logging.info(f"Cache saved to {filename}")
            except Exception as e:
                logging.error(f"Cache save error: {e}")

    def load_from_file(self, filename='dns_cache.pkl'):
        """Загружает кэш из файла"""
        try:
            with open(filename, 'rb') as f:
                self.cache = pickle.load(f)
                self.cleanup()  # Удаляем просроченные записи
                logging.info(f"Cache loaded from {filename}")
                return True
        except (FileNotFoundError, pickle.PickleError) as e1:
            logging.warning(f"Cache load failed (new cache will be created): {e1}")
            return False
        except Exception as e2:
            logging.error(f"Unexpected cache load error: {e2}")
            return False


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
        """Обработчик запросов с полной защитой от сбоев"""
        try:
            if not self.running:
                return

            request = dns.message.from_wire(data)
            if not request.question:
                return

            qname = request.question[0].name.to_text()
            qtype = request.question[0].rdtype
            logging.info(f"Query from {addr[0]}:{addr[1]} for {qname}")

            try:
                # 1. Попытка получить ответ из кеша
                if cached := self.cache.get_record(qname, qtype):
                    response = self._create_cached_response(request, qname, qtype, cached)
                # 2. Попытка запроса к старшему серверу
                elif self.is_internet_available():
                    response = self._query_upstream(request, qname)
                # 3. Возврат ошибки при отсутствии интернета
                else:
                    response = self._create_error_response(request, dns.rcode.REFUSED)

                self._send_response(response, addr)

            except Exception as e:
                logging.error(f"Processing error: {e}")
                self._send_error_response(data, addr)

        except ConnectionResetError:
            logging.warning("Client connection reset during processing")
        except Exception as e:
            logging.error(f"Critical error in handle_request: {e}")

    def _create_error_response(self, request, rcode):
        """Создает ответ с ошибкой"""
        response = dns.message.make_response(request)
        response.set_rcode(rcode)
        return response

    def _create_cached_response(self, request, qname, qtype, cached_records):
        """Создает ответ из кеша"""
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
        return response

    def _query_upstream(self, request, qname):
        """Устойчивый запрос к старшему серверу"""
        for attempt in range(2):  # 2 попытки
            try:
                if not self.running:
                    return None

                response = dns.query.udp(request, self.upstream_dns, timeout=2)
                if response.answer:
                    for rrset in response.answer:
                        self.cache.add_record(rrset)
                    return response

            except ConnectionResetError:
                if attempt == 1:  # Последняя попытка
                    return self._create_error_response(request, dns.rcode.SERVFAIL)
                time.sleep(0.1)
            except Exception as e:
                logging.error(f"Upstream attempt {attempt + 1} failed: {e}")

        return self._create_error_response(request, dns.rcode.SERVFAIL)

    def _send_response(self, response, addr):
        """Безопасно отправляет ответ клиенту"""
        if response and self.sock:
            try:
                self.sock.sendto(response.to_wire(), addr)
            except ConnectionResetError:
                logging.warning("Client connection reset during response")
            except Exception as e:
                logging.error(f"Failed to send response to {addr}: {e}")


    def _send_error_response(self, data, addr):
        """Создаёт и отправляет DNS-ответ с ошибкой при критических сбоях"""
        try:
            # Пытаемся разобрать оригинальный запрос
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)
            response.set_rcode(dns.rcode.REFUSED)  # Устанавливаем код ошибки сервера
            self.sock.sendto(response.to_wire(), addr)
        except Exception as e:
            logging.error(f"Failed to send error response: {e}")

    def start(self):
        """Запускает сервер с максимальной устойчивостью к ошибкам"""
        try:
            # Инициализация кеша
            if not self.cache.load_from_file():
                logging.warning("Starting with empty cache")

            # Настройка сокета с защитой от ошибок
            self._setup_socket()

            # Флаг запуска должен быть установлен в последнюю очередь
            self.running = True
            logging.info(f"DNS server started on port {self.port}")

            # Запуск фоновых процессов
            self._start_background_tasks()

            # Основной цикл обработки запросов
            self._run_main_loop()

        except Exception as e:
            logging.critical(f"Server startup failed: {e}")
            # Не вызываем stop() здесь - пусть управление перейдет в finally
            raise
        finally:
            # Только мягкое завершение, не блокируем исключения
            self._safe_shutdown()

    def _setup_socket(self):
        """Настройка сокета с защитой от ошибок"""
        try:
            if hasattr(self, 'sock') and self.sock:
                self.sock.close()

            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.settimeout(1)  # Таймаут для проверки флага running
            self.sock.bind(('127.0.0.1', self.port))
        except Exception as e:
            logging.error(f"Socket setup failed: {e}")
            raise

    def _start_background_tasks(self):
        """Запуск фоновых задач"""

        def cleanup_task():
            while self.running:
                time.sleep(60)
                try:
                    self.cache.cleanup()
                    self.cache.save_to_file()
                except Exception as e:
                    logging.error(f"Background task error: {e}")

        threading.Thread(target=cleanup_task, daemon=True).start()

    def _run_main_loop(self):
        """Основной цикл обработки запросов"""
        while self.running:
            try:
                data, addr = self.sock.recvfrom(512)
                threading.Thread(
                    target=self._safe_handle_request,
                    args=(data, addr),
                    daemon=True
                ).start()
            except socket.timeout:
                continue  # Нормальная ситуация для проверки флага
            except ConnectionResetError:
                logging.warning("Connection reset in main loop, continuing...")
                continue
            except OSError as e:
                if e.winerror == 10054:  # Специфичная обработка для Windows
                    logging.warning("Client forcibly closed connection in main loop")
                    continue
                logging.error(f"Socket error in main loop: {e}")
                break  # Выходим только при критических ошибках
            except Exception as e:
                logging.error(f"Unexpected error in main loop: {e}")
                continue  # Продолжаем работу при других ошибках

    def _safe_handle_request(self, data, addr):
        """Обработчик запросов с максимальной защитой"""
        try:
            self.handle_request(data, addr)
        except Exception as e:
            logging.error(f"Request handling crashed: {e}")
            # Сервер продолжает работать даже при падении обработчика

    def _safe_shutdown(self):
        """Безопасное завершение работы"""
        try:
            self.running = False
            if hasattr(self, 'sock') and self.sock:
                try:
                    self.sock.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                self.sock.close()
            self.cache.save_to_file()
        except Exception as e:
            logging.error(f"Shutdown error: {e}")
        finally:
            logging.info("Server resources released")

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


if __name__ == '__main__':
    server = DNSServer(port=53)
    try:
        server.start()
    except KeyboardInterrupt:
        pass  # Остановка через signal_handler
    except Exception as e14:
        logging.critical(f"Fatal error: {e14}")
        sys.exit(1)