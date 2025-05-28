import os
import re
import subprocess
import requests
import json
from ipaddress import ip_address, IPv4Address


class Tracer:
    def __init__(self):
        pass


    @staticmethod
    def is_valid_ip(ip):
        try:
            return isinstance(ip_address(ip), IPv4Address)
        except ValueError:
            return False

    def get_asn_info(self, ip):
        if not self.is_valid_ip(ip) or ip.startswith(('10.', '172.', '192.168.', '127.')):
            return None, None, None

        try:
            response = requests.get(f"https://stat.ripe.net/data/whois/data.json?resource={ip}", timeout=10)
            data = response.json()

            asn = None
            country = None
            provider = None

            records = data.get('data', {}).get('records', [])
            for record_group in records:
                for record in record_group:
                    key = record.get('key', '').lower()
                    value = record.get('value', '')

                    if key == 'origin':
                        asn = value
                    elif key == 'country':
                        country = value
                    elif key == 'netname':
                        provider = value

            return asn, country, provider
        except (requests.RequestException, json.JSONDecodeError):
            return None, None, None

    @staticmethod
    def trace_route(target):
        try:
            if os.name == 'nt':
                # Для Windows используем chcp 65001 для UTF-8 и tracert
                subprocess.run('chcp 65001', shell=True, check=True)
                process = subprocess.Popen(
                    ['tracert', '-d', target],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
            else:
                # Для Linux/macOS используем traceroute с LANG=C.UTF-8
                env = os.environ.copy()
                env['LANG'] = 'C.UTF-8'
                process = subprocess.Popen(
                    ['traceroute', '-n', target],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    env=env
                )

            output = []
            while True:
                line = process.stdout.readline()
                if not line:
                    break
                # Удаляем все не-ASCII символы
                clean_line = ''.join(char for char in line if ord(char) < 128)
                output.append(clean_line.strip())
                if '***' in clean_line:
                    break

            return output
        except subprocess.SubprocessError as e:
            print(f"Ошибка при выполнении трассировки: {e}")
            return None

    @staticmethod
    def parse_trace_output(output):
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        hops = []

        for line in output:
            if '***' in line:
                break

            # Извлекаем IP-адреса из строки
            ips = re.findall(ip_pattern, line)
            if not ips:
                continue

            # Первый IP в строке - это хост
            hop_ip = ips[0]
            hops.append(hop_ip)

        return hops
