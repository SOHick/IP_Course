from DNSServer import *
import sys

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dns_server.log'),
        logging.StreamHandler()
    ]
)

if __name__ == '__main__':
    server = DNSServer(port=53)
    try:
        server.start()
    except KeyboardInterrupt:
        pass  # Остановка через signal_handler
    except Exception as e14:
        logging.critical(f"Fatal error: {e14}")
        sys.exit(1)