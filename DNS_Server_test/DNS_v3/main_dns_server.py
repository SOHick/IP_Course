from DNSServer import *

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dns_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('DNSServer')

if __name__ == '__main__':
    server = DNSServer(port=1025)
    server.start()