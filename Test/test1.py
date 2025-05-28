import socket
import threading
import time
import pickle

CACHE_FILE = "cache.txt"  # имя файла для сохранения кэша
CACHE_TTL = 60  # время жизни записей в кэше (в секундах)


class DNSServer:
    def __init__(self):
        self.cache = {}  # кэш DNS записей
        self.load_cache()  # загрузка кэша из файла при запуске сервера

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # sock.bind(('127.0.0.1', 53))
        sock.bind(('127.0.0.1', 1025))  # запускаю так тк 53 он особый не получается (видимо особенность macOS)
        print("DNS server started")

        while True:
            data, addr = sock.recvfrom(1024)
            threading.Thread(target=self.handle_request, args=(data, addr)).start()

    def handle_request(self, data, addr):
        print(self.cache)
        query = parse_dns_query(data)
        for question in query['questions']:
            print(f"Received query for {question['name']}")

            if question['type'] == 'A':
                if question['name'] in self.cache and not is_expired(self.cache[question['name']]['expire_time']):
                    # если запись есть в кэше и не просрочена, отправляем ее клиенту
                    response = build_dns_response(data, self.cache[question['name']]['ip'])
                    print(f"Cache hit for {question['name']}")
                else:
                    # иначе делаем рекурсивный запрос к старшему DNS серверу
                    response = recursive_dns_query(data)
                    ip = parse_dns_response(response)['ip']
                    self.cache[question['name']] = {'ip': ip, 'expire_time': time.time() + CACHE_TTL}
                    print(f"Cache miss for {question['name']}, added to cache")

                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(response, addr)

    def load_cache(self):
        try:
            with open(CACHE_FILE, 'rb') as f:
                self.cache = pickle.load(f)
            print("Cache loaded from file")
        except:
            print("Cache file not found")

    def save_cache(self):
        with open(CACHE_FILE, 'wb') as f:
            pickle.dump(self.cache, f)
        print("Cache saved to file")

    def cleanup_cache(self):
        now = time.time()
        keys_to_delete = []
        for key in self.cache:
            if is_expired(self.cache[key]['expire_time']):
                keys_to_delete.append(key)
        for key in keys_to_delete:
            del self.cache[key]
        print("Cache cleaned up")


def is_expired(expire_time):
    return time.time() > expire_time


# парсинг DNS запроса (заголовка запроса и секции с вопросами)
# выход: словарь с информацией о запросе ( количество вопросов в запросе и
# список словарей, каждый из которых представляет собой один вопрос. Каждый вопрос
# содержит имя домена, тип записи и класс записи.)'''
def parse_dns_query(data):
    print(data, len(data))
    query = {}

    # первые 12 байт запроса содержат заголовок, включающий количество вопросов в запросе
    print(data[5])
    query['num_questions'] = int.from_bytes(data[5:6], byteorder='big')

    # следующие байты содержат секции с вопросами
    offset = 12
    questions = []
    for i in range(query['num_questions']):
        question = {}
        name = []
        while True and offset <= len(data):
            # print(offset)
            length = data[offset]
            if length == 0:
                offset += 1
                break
            name.append(data[offset + 1:offset + length + 1].decode('utf-8'))
            offset += length + 1
        question['name'] = '.'.join(name)
        question['type'] = data[offset:offset + 2].hex()
        question['class'] = data[offset + 2:offset + 4].hex()
        questions.append(question)
        offset += 4
    query['questions'] = questions
    print(query)
    return query


# парсинг DNS ответа
# парсинг заголовка ответа и секции с ответами, авторитетными и дополнительными записями
# выход: словарь с информацией об ответе (количество вопросов в запросе, количество ответов,
# авторитетных и дополнительных записей в ответе, а также списки словарей,
# каждый из которых представляет собой один ответ/авторитетную/дополнительную
# запись. Каждая запись содержит имя домена, тип записи, класс записи, TTL и данные)
def parse_dns_response(data):
    print('парсинг DNS ответа', data)
    response = {}

    # первые 12 байт ответа содержат заголовок
    # следующие 2 байта - количество вопросов в запросе
    response['num_questions'] = int.from_bytes(data[12:14], byteorder='big')

    # следующие 2 байта - количество ответов в ответе
    response['num_answers'] = int.from_bytes(data[14:16], byteorder='big')

    # следующие 2 байта - количество авторитетных записей в ответе
    response['num_authority'] = int.from_bytes(data[16:18], byteorder='big')

    # следующие 2 байта - количество дополнительных записей в ответе
    response['num_additional'] = int.from_bytes(data[18:20], byteorder='big')

    # следующие байты содержат секции с ответами
    offset = 20
    answers = []
    for i in range(response['num_answers']):
        answer = {}
        name = []
        while True:
            length = data[offset]
            if length == 0:
                offset += 1
                break
            name.append(data[offset + 1:offset + length + 1].decode('utf-8'))
            offset += length + 1
        answer['name'] = '.'.join(name)
        answer['type'] = data[offset:offset + 2].hex()
        answer['class'] = data[offset + 2:offset + 4].hex()
        answer['ttl'] = int.from_bytes(data[offset + 4:offset + 8], byteorder='big')
        answer['data_length'] = int.from_bytes(data[offset + 8:offset + 10], byteorder='big')
        answer['data'] = data[offset + 10:offset + 10 + answer['data_length']].hex()
        answers.append(answer)
        offset += 10 + answer['data_length']
    response['answers'] = answers

    # следующие байты содержат секции с авторитетными записями
    authority = []
    for i in range(response['num_authority']):
        name = []
        while True:
            length = data[offset]
            if length == 0:
                offset += 1
                break
            name.append(data[offset + 1:offset + length + 1].decode('utf-8'))
            offset += length + 1
        authority.append('.'.join(name))
        offset += 10
    response['authority'] = authority

    # следующие байты содержат секции с дополнительными записями
    additional = []
    for i in range(response['num_additional']):
        name = []
        while True:
            length = data[offset]
            if length == 0:
                offset += 1
                break
            name.append(data[offset + 1:offset + length + 1].decode('utf-8'))
            offset += length + 1
        additional.append('.'.join(name))
        offset += 10
    response['additional'] = additional
    print(response)
    return response


# построение DNS ответа
def build_dns_response(query_data, ip):
    # создаем заголовок ответа
    header = query_data[:2]  # копируем первые 2 байта из запроса
    header += bytes.fromhex('8180')  # добавляем флаги ответа (стандартный ответ + запись найдена)
    header += query_data[4:6]  # копируем идентификатор запроса
    header += bytes.fromhex('0001')  # количество ответов - 1
    header += bytes.fromhex('0000') * 3  # остальные поля заголовка заполняем нулями
    # создаем секцию с ответом
    answer = b'\xc0\x0c'  # указатель на имя домена вопроса (ответ на вопрос всегда содержит это же имя)
    answer += bytes.fromhex('0001')  # тип записи - A
    answer += bytes.fromhex('0001')  # класс записи - IN
    answer += bytes.fromhex('0000') + bytes.fromhex('0004')  # TTL и длина IP-адреса (в данном случае 4 байта)
    answer += socket.inet_aton(ip)  # преобразуем IP-адрес в бинарный формат и добавляем в ответ
    return header + query_data[12:] + answer


# выполнение рекурсивного DNS запроса
def recursive_dns_query(query_data):
    # выполнение рекурсивного DNS запроса
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query_data, ('8.8.8.8', 1025))  # отправляем запрос на старший DNS сервер
    data, _ = sock.recvfrom(1024)  # получаем ответ
    return data


dns_server = DNSServer()

try:
    dns_server.start()
except KeyboardInterrupt:
    dns_server.save_cache()

# для запуска
# nslookup ya.ru 127.0.0.1
# nslookup -port=1025 ya.ru 127.0.0.1