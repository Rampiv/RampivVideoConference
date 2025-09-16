// server.js
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "https://fancy-gnome-180787.netlify.app/",
        methods: ["GET", "POST"],
        allowedHeaders: ["Content-Type", "Authorization"]
    }
});

app.use(cors());
app.use(express.json());

// Обслуживание статических файлов из папки public
app.use(express.static('public'));

const PORT = process.env.PORT || 5000;

// Простая база данных пользователей (в реальном проекте используйте БД)
const users = [];

// JWT секретный ключ
const JWT_SECRET = 'your_jwt_secret_key';

// Регистрация пользователя
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }
    const existingUser = users.find(user => user.username === username);
    if (existingUser) {
        return res.status(400).json({ message: 'User already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });
    res.status(201).json({ message: 'User registered successfully' });
});

// Авторизация пользователя
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }
    const user = users.find(user => user.username === username);
    if (!user) {
        return res.status(400).json({ message: 'Invalid credentials' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
});

// Проверка токена
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Пространства имен для комнат
const rooms = {};

io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error('Authentication error'));
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return next(new Error('Authentication error'));
        socket.user = decoded.username;
        next();
    });
});

io.on('connection', (socket) => {
    console.log(`User ${socket.user} connected`);

    socket.on('joinRoom', (roomName) => {
        if (!rooms[roomName]) {
            rooms[roomName] = [];
        }
        rooms[roomName].push(socket.id);
        socket.join(roomName);
        console.log(`User ${socket.user} joined room ${roomName}`);
        io.to(roomName).emit('userJoined', socket.user, rooms[roomName]);
    });

    socket.on('leaveRoom', (roomName) => {
        if (rooms[roomName]) {
            rooms[roomName] = rooms[roomName].filter(id => id !== socket.id);
            if (rooms[roomName].length === 0) {
                delete rooms[roomName];
            }
        }
        socket.leave(roomName);
        console.log(`User ${socket.user} left room ${roomName}`);
        io.to(roomName).emit('userLeft', socket.user, rooms[roomName]);
    });

    socket.on('offer', (data) => {
        io.to(data.to).emit('offer', { from: socket.id, offer: data.offer });
    });

    socket.on('answer', (data) => {
        io.to(data.to).emit('answer', { from: socket.id, answer: data.answer });
    });

    socket.on('iceCandidate', (data) => {
        io.to(data.to).emit('iceCandidate', { from: socket.id, candidate: data.candidate });
    });

    socket.on('disconnect', () => {
        console.log(`User ${socket.user} disconnected`);
        for (const roomName in rooms) {
            if (rooms[roomName].includes(socket.id)) {
                rooms[roomName] = rooms[roomName].filter(id => id !== socket.id);
                if (rooms[roomName].length === 0) {
                    delete rooms[roomName];
                }
                io.to(roomName).emit('userLeft', socket.user, rooms[roomName]);
            }
        }
    });
});

server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});