from DNSServer import *
import logging

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


def main():
    """Точка входа в программу"""
    server = DNSServer(port=1024)
    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("Остановка сервера...")
        server.stop()
    except Exception as e:
        logger.error(f"Ошибка: {e}")
        server.stop()


if __name__ == '__main__':
    main()