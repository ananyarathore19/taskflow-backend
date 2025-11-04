require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();

// ===== CORS =====
// Allow requests from frontend (Render URL) and local dev
const corsOptions = {
    origin: [
        process.env.FRONTEND_URL || 'https://taskflow-frontend-xxxx.onrender.com', // Replace with your frontend URL if using .env
        'http://localhost:5173', // local dev
    ],
    credentials: true,
};
app.use(cors(corsOptions));
app.use(express.json());

// ===== MongoDB =====
const MONGODB_URI = process.env.MONGODB_URI || 'your-mongodb-uri-here';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

if (!MONGODB_URI) {
    console.error('❌ MONGODB_URI not found in .env file');
    process.exit(1);
}

mongoose.connect(MONGODB_URI)
    .then(() => console.log('✅ MongoDB connected'))
    .catch(err => { console.error(err); process.exit(1); });

// ===== Schemas =====
const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
    createdAt: { type: Date, default: Date.now },
});
const User = mongoose.model('User', userSchema);

const taskSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    title: String,
    description: String,
    completed: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
});
const Task = mongoose.model('Task', taskSchema);

// ===== Auth Middleware =====
const authMiddleware = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ message: 'No token' });

        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch {
        res.status(401).json({ message: 'Invalid or expired token' });
    }
};

// ===== Routes =====
app.get('/', (req, res) => res.json({ status: 'OK', message: 'API Running' }));

// --- Auth ---
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) return res.status(400).json({ message: 'All fields required' });

        if (await User.findOne({ email })) return res.status(400).json({ message: 'User exists' });

        const hashed = await bcrypt.hash(password, 10);
        const user = await User.create({ name, email, password: hashed });

        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
        res.status(201).json({ user: { id: user._id, name, email }, token });
    } catch (err) { res.status(500).json({ message: err.message }); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ message: 'Email & password required' });

        const user = await User.findOne({ email });
        if (!user) return res.status(401).json({ message: 'Invalid credentials' });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ message: 'Invalid credentials' });

        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ user: { id: user._id, name: user.name, email }, token });
    } catch (err) { res.status(500).json({ message: err.message }); }
});

// --- Tasks ---
app.get('/api/tasks', authMiddleware, async (req, res) => {
    try {
        const tasks = await Task.find({ userId: req.userId }).sort({ createdAt: -1 });
        res.json(tasks);
    } catch (err) { res.status(500).json({ message: err.message }); }
});

app.post('/api/tasks', authMiddleware, async (req, res) => {
    try {
        const { title, description } = req.body;
        if (!title) return res.status(400).json({ message: 'Title required' });

        const task = await Task.create({ userId: req.userId, title, description });
        res.status(201).json(task);
    } catch (err) { res.status(500).json({ message: err.message }); }
});

app.put('/api/tasks/:id', authMiddleware, async (req, res) => {
    try {
        const task = await Task.findOne({ _id: req.params.id, userId: req.userId });
        if (!task) return res.status(404).json({ message: 'Task not found' });

        Object.assign(task, req.body, { updatedAt: Date.now() });
        await task.save();
        res.json(task);
    } catch (err) { res.status(500).json({ message: err.message }); }
});

app.delete('/api/tasks/:id', authMiddleware, async (req, res) => {
    try {
        const task = await Task.findOneAndDelete({ _id: req.params.id, userId: req.userId });
        if (!task) return res.status(404).json({ message: 'Task not found' });
        res.json({ message: 'Deleted successfully' });
    } catch (err) { res.status(500).json({ message: err.message }); }
});

// ===== 404 & Error =====
app.use('*', (req, res) => res.status(404).json({ message: 'Route not found' }));

app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
});

// ===== Server =====
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Server running on port ${PORT}`));
