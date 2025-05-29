import threading
import time
import pickle
import os
from typing import Dict, Tuple, Optional
import logging

# Настройка логирования
logger = logging.getLogger(__name__)

class DNSCache:
    """Кэш DNS записей с автоматическим удалением просроченных записей"""
    def __init__(self):
        self.records: Dict[str, Dict[str, Tuple[bytes, int]]] = {}  # domain -> {type: (data, expiry)}
        self.lock = threading.RLock()
        self.cache_file = "dns_cache.pkl"

        if not os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'wb') as f:
                    pickle.dump({}, f)
                logger.info(f"Created new cache file at {os.path.abspath(self.cache_file)}")
            except Exception as e:
                logger.error(f"Failed to create cache file: {e}")

    def add_record(self, domain: str, rtype: str, data: bytes, ttl: int):
        """Добавляет запись в кэш"""
        expiry = time.time() + ttl
        with self.lock:
            if domain not in self.records:
                self.records[domain] = {}
            self.records[domain][rtype] = (data, expiry)

    def get_record(self, domain: str, rtype: str) -> Optional[bytes]:
        """Получает запись из кэша"""
        with self.lock:
            if domain not in self.records:
                return None
            if rtype not in self.records[domain]:
                return None

            data, expiry = self.records[domain][rtype]
            if time.time() < expiry:
                return data
            else:
                del self.records[domain][rtype]
                if not self.records[domain]:
                    del self.records[domain]
                return None

    def cleanup(self):
        """Удаляет просроченные записи"""
        now = time.time()
        with self.lock:
            for domain in list(self.records.keys()):
                for rtype in list(self.records[domain].keys()):
                    if now >= self.records[domain][rtype][1]:
                        del self.records[domain][rtype]
                if not self.records[domain]:
                    del self.records[domain]

    def save(self) -> bool:
        """Безопасное сохранение кэша с обработкой кодировки"""
        temp_file = self.cache_file + '.tmp'
        try:
            with self.lock:
                # Сохраняем во временный файл с явным указанием протокола
                with open(temp_file, 'wb') as f:
                    pickle.dump(self.records, f, protocol=pickle.HIGHEST_PROTOCOL)

            # Атомарная замена файла (работает на всех платформах)
            if os.path.exists(self.cache_file):
                os.replace(temp_file, self.cache_file)
            else:
                os.rename(temp_file, self.cache_file)

            logger.info(f"Cache successfully saved to {os.path.abspath(self.cache_file)}")
            return True
        except Exception as e:
            logger.error(f"Error saving cache: {e}")
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except Exception as e:
                    logger.error(f"Failed to remove temp file: {e}")
            return False

    def load(self) -> bool:
        """Безопасная загрузка кэша с обработкой кодировки"""
        try:
            if not os.path.exists(self.cache_file):
                logger.info("No cache file found, using empty cache")
                return True

            # Проверяем, что файл не пустой
            if os.path.getsize(self.cache_file) == 0:
                logger.warning("Cache file is empty, using empty cache")
                return True

            # Читаем файл в бинарном режиме
            with open(self.cache_file, 'rb') as f:
                data = pickle.load(f)

                if not isinstance(data, dict):
                    raise ValueError("Invalid cache data format")

                with self.lock:
                    self.records = data

            logger.info(f"Successfully loaded cache from {os.path.abspath(self.cache_file)}")
            return True
        except Exception as e:
            logger.error(f"Error loading cache: {e}")
            # Создаем новый пустой кэш при ошибке
            with self.lock:
                self.records = {}
            return False