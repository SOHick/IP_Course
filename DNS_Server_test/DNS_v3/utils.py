import socket
import time
import binascii
import struct


def get_current_seconds():
    return int(time.time())


def send_udp_message(msg, address, port, timeout=2):
    """Отправляет DNS-запрос и возвращает ответ"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # Проверяем, что адрес доступен
        try:
            socket.gethostbyname(address)
        except socket.gaierror:
            return None

        sock.sendto(msg, (address, port))
        response, _ = sock.recvfrom(4096)
        return response
    except socket.timeout:
        return None
    except Exception as e:
        return None
    finally:
        sock.close()


def decode_name(data, offset):
    """Декодирует доменное имя из DNS-пакета"""
    name = []
    while True:
        length = data[offset]
        if length == 0:
            break
        if (length & 0xc0) == 0xc0:  # Компрессия
            ptr_offset = struct.unpack('!H', data[offset:offset + 2])[
                             0] & 0x3fff
            part, _ = decode_name(data, ptr_offset)
            name.append(part)
            offset += 2
            break
        else:
            name.append(data[offset + 1:offset + 1 + length].decode('ascii'))
            offset += 1 + length
    return '.'.join(name), offset + 1


def encode_name(name):
    """Кодирует доменное имя для DNS-пакета"""
    encoded = bytearray()
    for part in name.split('.'):
        encoded.append(len(part))
        encoded.extend(part.encode('ascii'))
    encoded.append(0)
    return bytes(encoded)