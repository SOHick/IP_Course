import threading
import pickle
import logging
from datetime import datetime, timedelta
import dns.message
import dns.query
import dns.rrset
import dns.rdatatype
import dns.rdataclass
import dns.flags

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