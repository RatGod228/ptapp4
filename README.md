# ProfitTrack Pro

Полноценное веб-приложение для учета закупок и продаж с серверным хранением данных и реальной отправкой email.

## Функции

- ✅ Регистрация и вход пользователей
- ✅ Восстановление пароля по email (реальная отправка писем)
- ✅ Серверное хранение данных (доступ с любого устройства)
- ✅ Фото товаров
- ✅ Заметки к закупкам и продажам
- ✅ Учет остатков (FIFO)
- ✅ Множественные ветки (категории)
- ✅ Месячная сводка
- ✅ Система отзывов
- ✅ Темная/светлая тема

## Настройка Railway

### 1. Создание приложения

1. Зайдите на https://railway.app
2. Создайте новый проект
3. Выберите "Deploy from GitHub repo" или загрузите файлы напрямую
4. Выберите репозиторий с этим кодом

### 2. Настройка переменных окружения

В разделе "Variables" добавьте:

```
PORT=3000
JWT_SECRET=your-secret-key-here (сгенерируйте случайную строку)
```

### 3. Настройка SMTP для отправки email

Для реальной отправки email нужно настроить SMTP. Варианты:

#### Вариант A: Gmail

1. Включите 2FA в аккаунте Google
2. Создайте "App Password": https://myaccount.google.com/apppasswords
3. Добавьте переменные:

```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
SMTP_FROM=your-email@gmail.com
```

#### Вариант B: SendGrid

1. Зарегистрируйтесь на https://sendgrid.com
2. Создайте API Key
3. Добавьте переменные:

```
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASS=your-sendgrid-api-key
SMTP_FROM=your-verified-sender@example.com
```

#### Вариант C: Mailgun

1. Зарегистрируйтесь на https://mailgun.com
2. Добавьте переменные:

```
SMTP_HOST=smtp.mailgun.org
SMTP_PORT=587
SMTP_USER=postmaster@your-domain.mailgun.org
SMTP_PASS=your-mailgun-password
SMTP_FROM=noreply@your-domain.com
```

### 4. Деплой

1. Нажмите "Deploy"
2. Дождитесь завершения деплоя
3. Получите URL вашего приложения

## Структура проекта

```
profittrack-pro/
├── server.js          # Сервер с API
├── package.json       # Зависимости
├── public/
│   └── index.html     # React приложение
└── README.md          # Этот файл
```

## API Endpoints

### Auth
- `POST /api/auth/register` - Регистрация
- `POST /api/auth/login` - Вход
- `POST /api/auth/forgot-password` - Запрос кода восстановления
- `POST /api/auth/verify-code` - Проверка кода
- `POST /api/auth/reset-password` - Смена пароля
- `POST /api/auth/change-password` - Смена пароля (авторизованный)

### User
- `GET /api/user/profile` - Профиль пользователя
- `PUT /api/user/profile` - Обновление профиля

### Branches
- `GET /api/branches` - Список веток
- `POST /api/branches` - Создать ветку
- `DELETE /api/branches/:id` - Удалить ветку

### Purchases
- `GET /api/purchases` - Список закупок
- `POST /api/purchases` - Создать закупку
- `DELETE /api/purchases/:id` - Удалить закупку
- `PUT /api/purchases/:id/notes` - Обновить заметки

### Sales
- `GET /api/sales` - Список продаж
- `POST /api/sales` - Создать продажу
- `DELETE /api/sales/:id` - Удалить продажу
- `PUT /api/sales/:id/notes` - Обновить заметки

### Reviews
- `GET /api/reviews` - Список отзывов
- `POST /api/reviews` - Создать отзыв

## Локальный запуск

```bash
npm install
npm start
```

Приложение будет доступно на http://localhost:3000

## Важно

- Без настройки SMTP код восстановления пароля НЕ будет отправляться на email
- Данные хранятся в `/tmp/data` на сервере (Railway периодически очищает /tmp)
- Для постоянного хранения используйте внешнюю БД (MongoDB, PostgreSQL)
