# Дипломная работа
### Цель диплома: Создание веб-приложения — планировщика задач

____
- Для работы необходимо клонировать репозиторий и установить зависимости с помощью пакетного менеджера poetry (poetry
install).

### Разворачивание проекта
Клонировать проект из репозитория.
2. Создать виртуальное окружение.
3. Установить менеджер пакетов POETRY  (**pip install poetry**).
4. Выполнить команду **poetry update** для установки необходимых пакетов и зависимостей.
5. Создать в папке **src** проекта файл **.env** по примеру файла **.env_example** и определить в нём
соответствующие настройки переменных окружения.


   - **DEBUG**=True (Для PROD сервера должен быть установлен в False)
   - **SECRET_KEY**=*Секретный ключ* (сгенерируйте новый ключ для вашей версии проекта)
   - **DB_NAME**=*название БД*
   - **DB_USER**=*имя пользователя БД*
   - **DB_PASSWORD**=*пароль для подключения к БД*
   - **DB_HOST**=*хост размещения БД*
   - **DB_PORT**=*порт на котором работает БД*


6. Создать базу данных (**docker-compose up -d**).
7. Инициализируем миграции если они не сделаны (**python manage.py makemigrations**)
8. Накатываем миграции в БД (**python manage.py migrate**)
9. Создаём суперпользователя для админки (**python manage.py createsuperuser**)
10. Запускаем проект (**python manage.py runserver**)
