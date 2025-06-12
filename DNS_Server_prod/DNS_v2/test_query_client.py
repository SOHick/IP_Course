import socket
import dns.message

query = dns.message.make_query('dzen.ru', 'A')
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(query.to_wire(), ('127.0.0.1', 1025))
response_data, _ = sock.recvfrom(512)
response = dns.message.from_wire(response_data)
print(response)
