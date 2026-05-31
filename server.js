// 1. Инициализация переменных окружения (должна быть строго первой!)
require('dotenv').config();

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const nodemailer = require('nodemailer');
const http = require('http');
const { Server } = require('socket.io');
const { Pool } = require('pg'); 

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" }
});

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const SECRET_KEY = process.env.JWT_SECRET || 'nuntio-secret-key-2026';

// Проверяем, подтянулась ли строка из .env до старта пула подключений
if (!process.env.DATABASE_URL) {
  console.error("❌ ОШИБКА: Переменная DATABASE_URL не найдена в файле .env!");
  process.exit(1); 
}

// Настройка пула подключений к Neon.tech
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Автоматическое создание таблицы пользователей в Postgres при старте сервера
async function initDB() {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      email VARCHAR(100) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      avatar VARCHAR(255)
    );
  `;
  try {
    await pool.query(createTableQuery);
    console.log('🐘 Успешное подключение к Neon.tech и инициализация базы данных!');
  } catch (err) {
    console.error('❌ Ошибка инициализации Postgres:', err);
  }
}
initDB();

// Временные кэш-карты для кодов верификации (живут в оперативной памяти 10 минут)
const verificationCodes = new Map();
const resetCodes = new Map(); 

// Перенаправление с главного адреса на логин
app.get('/', (req, res) => {
  res.redirect('/login.html');
});

// Настройка отправщика писем через Gmail
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Функция генерации 6-значного цифрового кода
function generateCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ==================== ПРОВЕРКА ЮЗЕРНЕЙМА НА ЛЕТУ ====================
app.get('/api/users/check-username', async (req, res) => {
  try {
    const username = req.query.username;
    if (!username) return res.json({ available: true });

    const lowerUsername = username.trim().toLowerCase();
    
    // Ищем имя в БД без учета регистра
    const result = await pool.query('SELECT id FROM users WHERE LOWER(username) = $1', [lowerUsername]);
    
    if (result.rows.length > 0) {
      return res.json({ available: false });
    }

    // Проверяем среди тех, кто сейчас проходит регистрацию
    for (let [pendingEmail, pendingData] of verificationCodes.entries()) {
      if (pendingData.username.toLowerCase() === lowerUsername && pendingData.expires > Date.now()) {
        return res.json({ available: false });
      }
    }

    res.json({ available: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Ошибка сервера при проверке юзернейма' });
  }
});

// ==================== ПРОВЕРКА EMAIL НА ЛЕТУ ====================
app.get('/api/users/check-email', async (req, res) => {
  try {
    const email = req.query.email;
    if (!email) return res.json({ available: true });

    const lowerEmail = email.trim().toLowerCase();
    
    // Ищем email в БД
    const result = await pool.query('SELECT id FROM users WHERE LOWER(email) = $1', [lowerEmail]);
    
    if (result.rows.length > 0) {
      return res.json({ available: false });
    }

    // Проверяем среди ожидающих подтверждения кодом
    if (verificationCodes.has(lowerEmail)) {
      const pendingData = verificationCodes.get(lowerEmail);
      if (pendingData.expires > Date.now()) {
        return res.json({ available: false });
      }
    }

    res.json({ available: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Ошибка сервера при проверке email' });
  }
});

// ==================== РЕГИСТРАЦИЯ (ОТПРАВКА КОДА НА ПОЧТУ) ====================
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const emailCheck = await pool.query('SELECT id FROM users WHERE LOWER(email) = $1', [email.toLowerCase()]);
    if (emailCheck.rows.length > 0) {
      return res.status(400).json({ message: 'Пользователь с таким email уже зарегистрирован' });
    }

    const usernameCheck = await pool.query('SELECT id FROM users WHERE LOWER(username) = $1', [username.trim().toLowerCase()]);
    if (usernameCheck.rows.length > 0) {
      return res.status(400).json({ message: 'Этот юзернейм уже занят, выберите другой' });
    }

    const code = generateCode();
    const expires = Date.now() + 10 * 60 * 1000; 

    verificationCodes.set(email.toLowerCase(), { username, email, password, code, expires });

    await transporter.sendMail({
      from: `"Nuntio" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Код подтверждения Nuntio",
      html: `
        <div style="font-family: sans-serif; padding: 20px; background-color: #0a0a0a; color: #ffffff; border-radius: 16px;">
          <h2 style="color: #a78bfa;">Добро пожаловать в Nuntio!</h2>
          <p style="color: #a1a1aa;">Используйте этот code для подтверждения регистрации:</p>
          <div style="background: #111113; padding: 15px; border-radius: 12px; font-size: 24px; font-weight: bold; text-align: center; letter-spacing: 4px; color: #ffffff; border: 1px solid #1f1f22;">
            ${code}
          </div>
          <p style="color: #71717a; font-size: 12px; margin-top: 15px;">Код действителен 10 минут.</p>
        </div>
      `
    });

    res.json({ message: 'Код отправлен на почту', email });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Не удалось отправить код подтверждения.' });
  }
});

// ==================== ПРОВЕРКА КОДА И СОЗДАНИЕ АККАУНТА В БД ====================
app.post('/api/verify-code', async (req, res) => {
  const { email, code } = req.body;
  const data = verificationCodes.get(email.toLowerCase());

  if (!data) {
    return res.status(400).json({ message: 'Запрос устарел или не существует. Зарегистрируйтесь заново.' });
  }

  if (Date.now() > data.expires) {
    verificationCodes.delete(email.toLowerCase());
    return res.status(400).json({ message: 'Время действия кода истекло' });
  }

  if (data.code !== code) {
    return res.status(400).json({ message: 'Неверный код подтверждения' });
  }

  try {
    const hashedPassword = await bcrypt.hash(data.password, 10);
    const avatarUrl = `https://i.pravatar.cc/150?u=${data.username}`;

    // Записываем данные в таблицу Postgres на Neon
    const insertQuery = 'INSERT INTO users (username, email, password, avatar) VALUES ($1, $2, $3, $4)';
    await pool.query(insertQuery, [data.username, data.email.toLowerCase(), hashedPassword, avatarUrl]);

    verificationCodes.delete(email.toLowerCase()); 

    res.json({ message: 'Регистрация успешно завершена!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Ошибка при сохранении пользователя в базу данных' });
  }
});

// ==================== ВХОД (ЛОГИН) С РАЗДЕЛЬНЫМИ ОШИБКАМИ ====================
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const result = await pool.query('SELECT * FROM users WHERE LOWER(email) = $1', [email.toLowerCase()]);
    const user = result.rows[0];

    // 1. Если пользователя с такой почтой нет в базе вообще
    if (!user) {
      return res.status(404).json({ message: 'Пользователь с таким email не зарегистрирован' });
    }

    // 2. Если пользователь найден, но пароль не подошел
    if (!(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Неверный пароль' });
    }

    // Если всё ок — генерируем токен
    const token = jwt.sign(
      { id: user.id, username: user.username, email: user.email, avatar: user.avatar },
      SECRET_KEY,
      { expiresIn: '7d' }
    );

    res.json({ 
      token, 
      user: { id: user.id, username: user.username, email: user.email, avatar: user.avatar } 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Ошибка авторизации на сервере' });
  }
});

// ==================== ЗАПРОС НА ВОССТАНОВЛЕНИЕ ПАРОЛЯ ====================
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  
  try {
    const result = await pool.query('SELECT id FROM users WHERE LOWER(email) = $1', [email.toLowerCase()]);
    
    // Если аккаунт на этот email не найден — выводим четкую ошибку
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Пользователь с таким email не найден' });
    }

    const code = generateCode();
    const expires = Date.now() + 10 * 60 * 1000; 

    resetCodes.set(email.toLowerCase(), { code, expires });

    await transporter.sendMail({
      from: `"Nuntio" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Сброс пароля в Nuntio",
      html: `
        <div style="font-family: sans-serif; padding: 20px; background-color: #0a0a0a; color: #ffffff; border-radius: 16px;">
          <h2 style="color: #f43f5e;">Запрос на восстановление пароля</h2>
          <p style="color: #a1a1aa;">Используйте этот код, чтобы изменить свой пароль в Nuntio:</p>
          <div style="background: #111113; padding: 15px; border-radius: 12px; font-size: 24px; font-weight: bold; text-align: center; letter-spacing: 4px; color: #ffffff; border: 1px solid #1f1f22;">
            ${code}
          </div>
        </div>
      `
    });
    res.json({ message: 'Код для сброса пароля отправлен' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Не удалось отправить код восстановления.' });
  }
});

// ==================== СБРОС ПАРОЛЯ (УСТАНОВКА НОВОГО ПАРОЛЯ) ====================
app.post('/api/reset-password', async (req, res) => {
  const { email, code, newPassword } = req.body;
  const data = resetCodes.get(email.toLowerCase());

  if (!data) {
    return res.status(400).json({ message: 'Запрос устарел или не существует' });
  }

  if (Date.now() > data.expires) {
    resetCodes.delete(email.toLowerCase());
    return res.status(400).json({ message: 'Время действия кода истекло' });
  }

  if (data.code !== code) {
    return res.status(400).json({ message: 'Неверный код подтверждения' });
  }

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    const updateResult = await pool.query(
      'UPDATE users SET password = $1 WHERE LOWER(email) = $2 RETURNING id',
      [hashedPassword, email.toLowerCase()]
    );

    if (updateResult.rows.length === 0) {
      return res.status(404).json({ message: 'Пользователь не найден' });
    }

    resetCodes.delete(email.toLowerCase()); 
    res.json({ message: 'Пароль успешно изменен!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Ошибка при изменении пароля' });
  }
});

// ==================== ПОИСК ПОЛЬЗОВАТЕЛЕЙ ПО ИМЕНИ ====================
app.get('/api/users/search', async (req, res) => {
  try {
    if (!req.query.query) return res.json([]);
    
    const query = req.query.query.toLowerCase();
    const result = await pool.query(
      'SELECT id, username, avatar FROM users WHERE LOWER(username) LIKE $1',
      [`%${query}%`]
    );

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Ошибка поиска' });
  }
});

// ==================== СОКЕТЫ (ОНЛАЙН И ПРИВАТНЫЕ СООБЩЕНИЯ) ====================
const onlineUsers = new Map(); 

io.on('connection', (socket) => {
  socket.on('user_connected', (userId) => {
    onlineUsers.set(userId, socket.id);
  });

  socket.on('send_private_message', ({ senderId, receiverId, text, senderName, senderAvatar }) => {
    const receiverSocketId = onlineUsers.get(receiverId);
    
    const messageData = {
      senderId,
      text,
      senderName,
      senderAvatar,
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    if (receiverSocketId) {
      io.to(receiverSocketId).emit('receive_private_message', messageData);
    }
    
    socket.emit('message_sent_success', messageData);
  });

  socket.on('disconnect', () => {
    for (let [userId, socketId] of onlineUsers.entries()) {
      if (socketId === socket.id) {
        onlineUsers.delete(userId);
        break;
      }
    }
  });
});

// Запуск сервера на 3000 порту
const PORT = 3000;
server.listen(PORT, () => {
  console.log(`🚀 Сервер Nuntio запущен на http://localhost:${PORT}`);
});