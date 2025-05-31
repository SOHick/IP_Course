import pickle
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import logging


logger = logging.getLogger(__name__)
class DNSCache:
    """Оптимизированный кэш DNS записей с автоматическим удалением просроченных записей"""
    __slots__ = ['_forward', '_reverse', '_ns', '_lock']

    def __init__(self):
        self._forward: Dict[str, Tuple[str, datetime]] = {}  # domain -> (ip, expiry)
        self._reverse: Dict[str, Tuple[str, datetime]] = {}  # ip -> (domain, expiry)
        self._ns: Dict[str, List[Tuple[str, datetime]]] = {}  # domain -> [(ns, expiry)]
        self._lock = threading.RLock()

    def add_record(self, domain: str, ip: str, ttl: int) -> None:
        """Добавляет A и PTR записи в кэш"""
        expiry = datetime.now() + timedelta(seconds=ttl)
        with self._lock:
            self._forward[domain.lower()] = (ip, expiry)
            self._reverse[ip] = (domain.lower(), expiry)

    def add_ns_record(self, domain: str, ns: str, ttl: int) -> None:
        """Добавляет NS запись в кэш"""
        expiry = datetime.now() + timedelta(seconds=ttl)
        with self._lock:
            if domain.lower() not in self._ns:
                self._ns[domain.lower()] = []
            self._ns[domain.lower()].append((ns.lower(), expiry))

    def get_record(self, domain: str) -> Optional[str]:
        """Получает A запись из кэша"""
        domain = domain.lower()
        with self._lock:
            if domain not in self._forward:
                return None

            ip, expiry = self._forward[domain]
            if datetime.now() < expiry:
                return ip

            # Удаляем просроченную запись
            del self._forward[domain]
            if ip in self._reverse:
                del self._reverse[ip]
            return None

    def get_ns_records(self, domain: str) -> Optional[List[str]]:
        """Получает NS записи для домена"""
        domain = domain.lower()
        with self._lock:
            if domain not in self._ns:
                return None

            now = datetime.now()
            valid_records = []
            expired_indices = []

            for i, (ns, expiry) in enumerate(self._ns[domain]):
                if now < expiry:
                    valid_records.append(ns)
                else:
                    expired_indices.append(i)

            # Удаляем просроченные записи в обратном порядке
            for i in reversed(expired_indices):
                del self._ns[domain][i]

            if not valid_records:
                del self._ns[domain]
                return None

            return valid_records

    def cleanup(self) -> None:
        """Очищает просроченные записи"""
        now = datetime.now()
        with self._lock:
            # Очистка A записей
            expired_domains = [d for d, (_, e) in self._forward.items() if now >= e]
            for domain in expired_domains:
                ip = self._forward[domain][0]
                del self._forward[domain]
                if ip in self._reverse:
                    del self._reverse[ip]

            # Очистка NS записей
            expired_ns = [d for d, records in self._ns.items()
                          if all(now >= e for _, e in records)]
            for domain in expired_ns:
                del self._ns[domain]

    def save(self, filename: str = 'dns_cache.txt') -> bool:
        print("dsadasdas")
        """Сохраняет кэш на диск"""
        with self._lock:
            try:
                with open(filename, 'wb') as f:
                    data = {
                        'forward': self._forward,
                        'reverse': self._reverse,
                        'ns': self._ns
                    }
                    pickle.dump(data, f)
                return True
            except Exception as e:
                logger.error(f"Ошибка сохранения кэша: {e}")
                return False

    def load(self, filename: str = 'dns_cache.txt') -> bool:
        """Загружает кэш с диска"""
        try:
            with open(filename, 'rb') as f:
                data = pickle.load(f)
                with self._lock:
                    self._forward = data.get('forward', {})
                    self._reverse = data.get('reverse', {})
                    self._ns = data.get('ns', {})
                    self.cleanup()  # Удаляем просроченные записи
            return True
        except FileNotFoundError:
            logger.info("Файл кэша не найден, будет создан новый")
            return False
        except Exception as e:
            logger.error(f"Ошибка загрузки кэша: {e}")
            return False