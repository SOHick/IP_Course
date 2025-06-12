import threading
import pickle
import logging
from datetime import datetime, timedelta
import dns.message
import dns.query
import dns.rrset
import dns.rdatatype
import dns.rdataclass
logger = logging.getLogger(__name__)

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
