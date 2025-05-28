import socket
from as_tracer import *

class Main_Function:
    @staticmethod
    def main():
        Tr = Tracer()
        print("Трассировка автономных систем с определением страны и провайдера")
        print("Введите доменное имя или IP-адрес:")
        target = input().strip()

        # Проверяем, является ли ввод IP-адресом или доменным именем
        try:
            if not Tr.is_valid_ip(target):
                # Преобразуем доменное имя в IP
                target_ip = socket.gethostbyname(target)
                print(f"Доменное имя {target} преобразовано в IP: {target_ip}")
        except socket.gaierror:
            print("Ошибка: не удалось разрешить доменное имя")
            return

        print("\nВыполняем трассировку...")
        trace_output = Tr.trace_route(target)

        if not trace_output:
            print("Ошибка при выполнении трассировки")
            return

        print("\nРезультат трассировки:")
        for line in trace_output:
            print(line)

        print("\nАнализируем автономные системы...")
        hops = Tr.parse_trace_output(trace_output)

        if not hops:
            print("Не удалось извлечь IP-адреса из результатов трассировки")
            return

        # Создаем таблицу результатов
        results = []
        for i, ip in enumerate(hops, 1):
            asn, country, provider = Tr.get_asn_info(ip)
            results.append({
                'hop': i,
                'ip': ip,
                'asn': asn if asn else "N/A (private/local)",
                'country': country if country else "N/A",
                'provider': provider if provider else "N/A"
            })

        # Выводим результаты в виде таблицы
        print("\nРезультаты:")
        print(f"{'№':<5} | {'IP':<15} | {'AS':<10} | {'Страна':<10} | {'Провайдер'}")
        print("-" * 70)
        for result in results:
            print(
                f"{result['hop']:<5} | {result['ip']:<15} | {result['asn']:<10} | {result['country']:<10} | {result['provider']}")


if __name__ == "__main__":
    try:
        Main_Function.main()
    except KeyboardInterrupt:
        print("\nПрограмма прервана пользователем")
    except Exception as e:
        print(f"Произошла ошибка: {str(e)}")