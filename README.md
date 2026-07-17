# Jartix Launcher Server

Серверная часть системы лаунчера. Включает:
- REST API для лаунчера (регистрация, авторизация, HWID, ключи)
- Админ-панель для управления ключами и пользователями
- Стриминг зашифрованного клиента (файлы НЕ хранятся на ПК пользователя)

## Быстрый старт

```bash
cd launcher-server
npm install
npm start
```

Сервер запустится на `http://localhost:3000`
Админ-панель: `http://localhost:3000/admin`

**Дефолтный логин:** admin / admin123

## Структура

```
launcher-server/
├── server.js          # Точка входа
├── db.js              # SQLite база + HWID хеширование
├── api.js             # REST API для лаунчера
├── admin.js           # Админ API + роуты
├── public/
│   └── admin.html     # Админ-панель
└── client/
    ├── Launcher.java  # Java-лаунчер
    └── client.jar     # Загружается через админку
```

## API Эндпоинты

### Авторизация
| Метод | Путь | Описание |
|-------|------|----------|
| POST | `/api/auth/register` | Регистрация `{username, password}` |
| POST | `/api/auth/login` | Вход `{username, password}` → `{token}` |

### Лаунчер
| Метод | Путь | Описание |
|-------|------|----------|
| POST | `/api/launcher/activate` | Активация ключа `{key, hwid}` |
| POST | `/api/launcher/validate` | Валидация сессии `{hwid}` → `{session}` |
| GET | `/api/launcher/client` | Стриминг зашифрованного клиента |
| GET | `/api/launcher/version` | Текущая версия клиента |

### Админ
| Метод | Путь | Описание |
|-------|------|----------|
| POST | `/admin/api/login` | Вход в админку |
| GET | `/admin/api/stats` | Статистика |
| GET | `/admin/api/keys` | Список ключей |
| POST | `/admin/api/keys/generate` | Генерация ключей |
| DELETE | `/admin/api/keys/:id` | Деактивация ключа |
| GET | `/admin/api/users` | Список пользователей |
| POST | `/admin/api/users/:id/reset-hwid` | Сброс HWID |
| GET | `/admin/api/logs` | Логи событий |
| POST | `/admin/api/client/upload` | Загрузка client.jar |

## HWID Система

HWID генерируется из:
1. Серийный номер материнской платы
2. Processor ID CPU
3. Серийный номер диска

Хешируется через SHA-256. Привязка: 1 ключ → 1 HWID.

## Ключи

Формат: `JX-XXXXX-XXXXX-XXXXX-XXXXX`
- 4 сегмента по 5 символов
- Символы: A-Z, 2-9 (без O, 0, I, 1 для читаемости)

## Шифрование клиента

Клиентский JAR шифруется AES-256-CBC перед отправкой:
1. Сервер генерирует случайный IV (16 байт)
2. Шифрует JAR AES-256-CBC
3. Отправляет: IV + зашифрованные данные
4. Лаунчер расшифровывает в оперативной памяти
5. Temp-файл удаляется сразу после загрузки

## Деплой

### Бесплатно:
- **Railway.app** — $5/мес free tier, Node.js, автоматический деплой с GitHub
- **Render.com** — free tier, Node.js, автоматический деплой
- **Glitch.com** — бесплатно, но засыпает через 5 мин без трафика
- **Oracle Cloud** — бесплатный VPS навсегда (нужна карта для верификации)

### Платно (рекомендуется):
- **DigitalOcean** — $6/мес, надёжный VPS
- **Hetzner** — €4/мес, быстрый VPS в Европе
- **Vultr** — $5/мес, много локаций

### Пошагово (Railway):
1. Создай аккаунт на railway.app
2. Подключи GitHub репозиторий
3. Railway автоматически определит Node.js
4. Добавь переменные окружения: `ENCRYPTION_KEY`, `JWT_SECRET`
5. Деплой

### Пошагово (Render):
1. Создай аккаунт на render.com
2. New → Web Service → подключи репозиторий
3. Build: `npm install`
4. Start: `node server.js`
5. Добавь env vars

### После деплоя:
1. Открой админку: `https://your-app.onrender.com/admin`
2. Загрузи client.jar через вкладку "Клиент"
3. Сгенерируй ключи
4. Настрой лаунчер на URL сервера
