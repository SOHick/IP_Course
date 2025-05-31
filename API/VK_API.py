import os
import requests


class VK_API:

    def __init__(self, id_or_url: str, vk_token: str) -> None:
        self.response = None
        self.VK_tkn = "Вставить свой access_token"

        # Определяем переменную user_info и передаем ей GET-запрос для получения информации о пользователе
        user_info = requests.get("https://api.vk.com/method/users.get", params={
            "access_token": self.VK_tkn,  # Передаем токен VK API
            "v": "5.199",  # Версия VK API
            "user_ids": id_or_url,  # ID пользователя VK
            "name_case": "gen"  # Падеж для имени пользователя
        })

        # Обрабатываем исключения и определяем атрибуты user_id и user_info
        try:
            self.user_id = user_info.json()["response"][0]["id"]
            self.user_info = user_info.json()["response"][0]
        except KeyError:
            print("error receiving user data")
            raise

    # метод для вывода списка друзей пользователей VK
    def print_friends(self) -> None:
        # Если ответ на запрос получен
        if self.response:
            # Выводится информация о друзьях пользователя
            print(f"\nДрузья {self.user_info['first_name']} {self.user_info['last_name']}:  \n")
            # Итерация по списку друзей пользователя
            counter = 1
            for i in self.response.json()["response"]["items"]:
                # Выводится информация о каждом друге
                print(f'{counter})\t{i["first_name"]} {i["last_name"]} - id: {i["id"]}')
                counter += 1
        # Если ответ на запрос не получен
        else:
            # Отправляется новый запрос на получение списка друзей пользователя
            self.response = requests.get("https://api.vk.com/method/friends.get", params={
                "access_token": self.VK_tkn,
                "v": "8.131",
                "user_id": self.user_id,
                "fields": "city",
                "order": "name"
            })
            # Рекурсивный вызов
            self.print_friends()


def main():
    vktoken = os.environ.get("VK_tkn")  # Получаем токен VK API из переменной окружения
    name = input("input user_id or short_url: ")  # Получаем ID пользователя VK
    Api = VK_API(name, vktoken)
    Api.print_friends()


if __name__ == '__main__':
    main()