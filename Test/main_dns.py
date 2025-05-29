from DNSServer import *

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('dns_server.log')
    ]
)
logger = logging.getLogger('DNSServer')



if __name__ == '__main__':
    try:
        ser = DNSServer(port=1025)
        ser.start()
    except KeyboardInterrupt:
        ser.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        ser.stop()