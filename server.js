const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const path = require('path');

const app = express();

// በማንኛውም ብራውዘር እና መሳሪያ እንዳይዘጋ CORS መፍቀድ
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_tech_transfer_key_2026';

// ---------------- MongoDB Connection ----------------
// Render/Railway ላይ Environment Variable MONGODB_URI ማስገባት ትችላለህ
const MONGODB_URI = process.env.MONGODB_URI || "እዚህ_ጋር_የእርስዎን_MongoDB_Atlas_URI_ያስገቡ";

mongoose.connect(MONGODB_URI)
    .then(() => console.log('⚡ Connected to MongoDB Atlas successfully!'))
    .catch(err => console.error('❌ MongoDB Connection Error:', err));

// ---------------- MongoDB Schemas ----------------
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, required: true, enum: ['superadmin', 'admin', 'user'] },
    created_at: { type: Date, default: Date.now }
});

const reportSchema = new mongoose.Schema({
    zone: String,
    poly: String,
    techName: String,
    coordinator: String,
    phone: String,
    sector: String,
    valueChain: String,
    techType: String,
    year: String,
    transferQty: Number,
    transferSector: String,
    resource: Number,
    b_ent: Number,
    b_mobile: Number,
    b_male: Number,
    b_female: Number,
    diagnosis: Number,
    createdBy: String,
    created_at: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Report = mongoose.model('Report', reportSchema);

// Auth Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'ያልተፈቀደ መግቢያ! እባክዎ መጀመሪያ ይግቡ።' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'የሴሽን ጊዜዎ አልፎአል ወይም የተሳሳተ ቶከን ነው!' });
        req.user = user;
        next();
    });
};

// ==================== API ROUTES ====================

// 1. Health Check (ሰርቨሩ እየሰራ መሆኑን በማንኛውም ብራውዘር ለማየት)
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'Server is running smoothly!' });
});

// 2. Initialize Superadmin Auto/Manual
const initSuperadmin = async () => {
    try {
        const exist = await User.findOne({ role: 'superadmin' });
        if (!exist) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await User.create({
                username: 'superadmin',
                password: hashedPassword,
                role: 'superadmin'
            });
            console.log('✅ Default superadmin account created (superadmin / admin123)');
        }
    } catch (err) {
        console.error('Superadmin init error:', err);
    }
};
initSuperadmin();

app.post('/api/init-superadmin', async (req, res) => {
    await initSuperadmin();
    res.json({ message: 'Superadmin check/initialization completed!' });
});

// 3. Login Endpoint
app.post('/api/login', async (req, res) => {
    const { username, password, role } = req.body;

    if (!username || !password || !role) {
        return res.status(400).json({ error: 'እባክዎ ሁሉንም መስኮች ይሙሉ!' });
    }

    try {
        const user = await User.findOne({ username: username.trim(), role: role.trim() });
        if (!user) {
            return res.status(400).json({ error: 'የተጠቃሚው ስም ወይም ሚና አልተገኘም!' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'የተሳሳተ የይለፍ ቃል!' });
        }

        const token = jwt.sign(
            { id: user._id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '12h' }
        );

        res.json({
            message: 'በተሳካ ሁኔታ ገብተዋል',
            token: token,
            role: user.role,
            username: user.username
        });
    } catch (err) {
        res.status(500).json({ error: 'የሰርቨር ስህተት ተከሰቷል!' });
    }
});

// 4. Manage Users
app.get('/api/users', authenticateToken, async (req, res) => {
    try {
        const users = await User.find({}, '-password');
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/users', authenticateToken, async (req, res) => {
    if (req.user.role !== 'superadmin') {
        return res.status(403).json({ error: 'ፈቃድ የለዎትም!' });
    }
    const { username, password, role } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await User.create({ username, password: hashedPassword, role });
        res.json({ message: 'ተጠቃሚ ተፈጥሯል!', user: { id: newUser._id, username, role } });
    } catch (err) {
        res.status(400).json({ error: 'የተጠቃሚ ስም ቀደም ሲል ተይዟል!' });
    }
});

app.delete('/api/users/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'superadmin') {
        return res.status(403).json({ error: 'ፈቃድ የለዎትም!' });
    }
    try {
        await User.findByIdAndDelete(req.params.id);
        res.json({ message: 'ተጠቃሚው ተሰርዟል!' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 5. Reports API
app.post('/api/report', authenticateToken, async (req, res) => {
    try {
        const newReport = await Report.create({ ...req.body, createdBy: req.user.username });
        res.json({ message: 'ሪፖርቱ ተመዝግቧል!', id: newReport._id });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/report', authenticateToken, async (req, res) => {
    try {
        const reports = await Report.find().sort({ created_at: -1 });
        res.json(reports);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Front-End SPA Fallback
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running globally on port ${PORT}`);
});
