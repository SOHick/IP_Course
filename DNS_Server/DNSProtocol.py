import socket
from typing import Dict, List, Tuple,  Union
import logging

logger = logging.getLogger(__name__)

class DNSProtocol:
    """Обработка DNS протокола (запросы и ответы)"""

    @staticmethod
    def parse_query(data: bytes) -> Dict[str, Union[bytes, str]]:
        """Парсит DNS запрос"""
        try:
            # Чтение заголовка
            transaction_id = data[:2]
            flags = data[2:4]
            questions = int.from_bytes(data[4:6], 'big')

            # Парсинг вопроса
            pos = 12
            labels = []
            while True:
                length = data[pos]
                if length == 0:
                    break
                labels.append(data[pos + 1:pos + 1 + length].decode('ascii'))
                pos += 1 + length
            qname = '.'.join(labels)
            pos += 1

            qtype = data[pos:pos + 2]
            qclass = data[pos + 2:pos + 4]

            return {
                'id': transaction_id,
                'flags': flags,
                'questions': questions,
                'qname': qname,
                'qtype': qtype,
                'qclass': qclass
            }
        except Exception as e:
            raise ValueError(f"Ошибка парсинга запроса: {e}")

    @staticmethod
    def build_response(query: Dict, answers: List[bytes],
                       authority: List[bytes], additional: List[bytes]) -> bytes:
        """Строит DNS ответ"""
        response = query['id'] + b'\x81\x80'  # Флаги: Response, Recursion Available
        response += (1).to_bytes(2, 'big')  # Questions
        response += len(answers).to_bytes(2, 'big')  # Answers
        response += len(authority).to_bytes(2, 'big')  # Authority
        response += len(additional).to_bytes(2, 'big')  # Additional

        # Вопрос
        for label in query['qname'].split('.'):
            response += len(label).to_bytes(1, 'big') + label.encode('ascii')
        response += b'\x00' + query['qtype'] + query['qclass']

        # Ответы
        for section in (answers, authority, additional):
            response += b''.join(section)

        return response

    @staticmethod
    def parse_response(data: bytes) -> List[Dict]:
        """Парсит DNS ответ и извлекает все записи"""
        records = []
        pos = 12  # Пропускаем заголовок

        # Пропускаем вопрос
        while data[pos] != 0:
            pos += 1 + data[pos]
        pos += 5  # Пропускаем QTYPE и QCLASS

        # Читаем количество записей
        an_count = int.from_bytes(data[6:8], 'big')
        ns_count = int.from_bytes(data[8:10], 'big')
        ar_count = int.from_bytes(data[10:12], 'big')

        # Обрабатываем все записи
        for _ in range(an_count + ns_count + ar_count):
            record, pos = DNSProtocol._parse_record(data, pos)
            records.append(record)

        return records

    @staticmethod
    def _parse_record(data: bytes, pos: int) -> Tuple[Dict, int]:
        """Парсит одну ресурсную запись"""
        # Пропускаем имя (может быть сжатым)
        if (data[pos] & 0xC0) == 0xC0:
            pos += 2
        else:
            while data[pos] != 0:
                pos += 1 + data[pos]
            pos += 1

        # Читаем тип, класс, TTL и длину данных
        rtype = data[pos:pos + 2]
        rclass = data[pos + 2:pos + 4]
        ttl = int.from_bytes(data[pos + 4:pos + 8], 'big')
        rdlength = int.from_bytes(data[pos + 8:pos + 10], 'big')
        rdata = data[pos + 10:pos + 10 + rdlength]
        pos += 10 + rdlength

        # Обрабатываем разные типы записей
        record = {'ttl': ttl}

        if rtype == b'\x00\x01':  # A
            record.update({
                'type': 'A',
                'name': '',
                'ip': socket.inet_ntoa(rdata)
            })
        elif rtype == b'\x00\x1c':  # AAAA
            record.update({
                'type': 'AAAA',
                'name': '',
                'ip': socket.inet_ntop(socket.AF_INET6, rdata)
            })
        elif rtype == b'\x00\x02':  # NS
            record.update({
                'type': 'NS',
                'name': DNSProtocol._parse_name(data, pos - rdlength)
            })
        elif rtype == b'\x00\x0c':  # PTR
            record.update({
                'type': 'PTR',
                'name': DNSProtocol._parse_name(data, pos - rdlength)
            })
        else:
            record['type'] = 'UNKNOWN'

        return record, pos

    @staticmethod
    def _parse_name(data: bytes, pos: int) -> str:
        """Парсит доменное имя (может быть сжатым)"""
        labels = []
        while True:
            if (data[pos] & 0xC0) == 0xC0:
                # Сжатое имя
                offset = int.from_bytes(data[pos:pos + 2], 'big') & 0x3FFF
                labels.append(DNSProtocol._parse_name(data, offset))
                pos += 2
                break
            length = data[pos]
            if length == 0:
                pos += 1
                break
            labels.append(data[pos + 1:pos + 1 + length].decode('ascii'))
            pos += 1 + length
        return '.'.join(labels)

    @staticmethod
    def build_a_record(name: str, ip: str, ttl: int) -> bytes:
        """Строит A запись для ответа"""
        # Имя (может быть сжатым)
        record = b'\xc0\x0c'

        # Тип, класс, TTL
        record += b'\x00\x01\x00\x01'
        record += ttl.to_bytes(4, 'big')

        # Данные (IP)
        record += b'\x00\x04'
        record += socket.inet_aton(ip)

        return record

    @staticmethod
    def build_ns_record(name: str, ns: str, ttl: int) -> bytes:
        """Строит NS запись для ответа"""
        # Имя (может быть сжатым)
        record = b'\xc0\x0c'

        # Тип, класс, TTL
        record += b'\x00\x02\x00\x01'
        record += ttl.to_bytes(4, 'big')

        # Данные (NS сервер)
        ns_labels = ns.split('.')
        ns_data = b''
        for label in ns_labels:
            ns_data += len(label).to_bytes(1, 'big') + label.encode('ascii')
        ns_data += b'\x00'

        record += len(ns_data).to_bytes(2, 'big')
        record += ns_data

        return record