const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

// የደህንነት ፓኬጆች
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// dotenv ማዋቀር (ከተቻለ .env ፋይል በመጠቀም ሚስጥራዊ መረጃዎችን መያዝ)
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'tech_transfer_secret_key_2018';

// --- Security Middlewares ---
// 1. የ HTTP Headers ደህንነትን በ Helmet ማጠናከር
app.use(helmet());

// 2. የጥያቄ ብዛት መገደብ (Rate Limiting - Brute-force ጥቃቶችን ለመከላከል)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // ለ 15 ደቂቃዎች
    max: 100, // ከአንድ IP አድራሻ ከፍተኛው የጥያቄ ብዛት
    message: { error: 'በጣም ብዙ ጥያቄዎች ከዚህ IP መጥተዋል፣ እባክዎ ቆይተው ይሞክሩ።' }
});
app.use('/api/', limiter);

// Middleware
app.use(express.json());
app.use(cors());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Ensure upload directory exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

// MongoDB Connection
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/tech_transfer_db';

mongoose.connect(MONGO_URI)
    .then(() => console.log('MongoDB Connected Successfully.'))
    .catch(err => console.error('MongoDB Connection Error:', err));

// --- Schemas & Models ---
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, trim: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin', 'superadmin'], default: 'user' }
});
const User = mongoose.model('User', UserSchema);

const ReportSchema = new mongoose.Schema({
    zone: { type: String, required: true },
    poly: String,
    techName: String,
    coordinator: String,
    phone: String,
    sector: String,
    valueChain: String,
    techType: String,
    year: Number,
    transferQty: Number,
    transferSector: String,
    resource: Number,
    b_ent: { type: Number, default: 0 },
    b_mobile: { type: Number, default: 0 },
    b_male: { type: Number, default: 0 },
    b_female: { type: Number, default: 0 },
    diagnosis: String,
    photoUrl: String,
    videoUrl: String,
    createdBy: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});
const Report = mongoose.model('Report', ReportSchema);

// --- Multer Storage ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, './uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }
});

// --- Auth Middleware ---
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'መግቢያ ፈቃድ (Token) የለም!' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'ፈቃዱ አላለፈም ወይም ልክ አይደለም!' });
        req.user = user;
        next();
    });
}

// --- Seed Superadmin ---
async function createSuperadmin() {
    try {
        const admin = await User.findOne({ username: 'superadmin' });
        if (!admin) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await User.create({ username: 'superadmin', password: hashedPassword, role: 'superadmin' });
            console.log('Superadmin initialized.');
        }
    } catch (err) {
        console.error('Superadmin check error:', err.message);
    }
}
createSuperadmin();

// --- API Routes ---

// Login
app.post(['/api/auth/login', '/api/login'], async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ error: 'የተጠቃሚ ስም ወይም የይለፍ ቃል ስህተት ነው!' });
        }
        const token = jwt.sign({ id: user._id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, role: user.role, username: user.username });
    } catch (err) {
        res.status(500).json({ error: 'Server Error' });
    }
});

// Get Current User Profile
app.get('/api/me', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) return res.status(404).json({ error: 'ተጠቃሚው አልተገኘም' });
        res.json({ username: user.username, role: user.role });
    } catch (err) {
        res.status(500).json({ error: 'Server Error' });
    }
});

// User Management Routes
app.get('/api/users', verifyToken, async (req, res) => {
    try {
        const users = await User.find().select('-password');
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: 'Server Error' });
    }
});

app.post('/api/users', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'superadmin' && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'ፈቃድ የለዎትም!' });
        }
        const { username, password, role } = req.body;
        const existing = await User.findOne({ username });
        if (existing) return res.status(400).json({ error: 'ይህ የተጠቃሚ ስም უკვე አለ!' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await User.create({ username, password: hashedPassword, role: role || 'user' });
        res.status(201).json({ message: 'ተጠቃሚው ተፈጥሯል', username: newUser.username });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/users/:username', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'ፈቃድ የለዎትም!' });
        await User.findOneAndDelete({ username: req.params.username });
        res.json({ message: 'ተጠቃሚው ተሰርዟል' });
    } catch (err) {
        res.status(500).json({ error: 'Server Error' });
    }
});

app.put('/api/users/:username/password', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'ፈቃድ የለዎትም!' });
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        await User.findOneAndUpdate({ username: req.params.username }, { password: hashedPassword });
        res.json({ message: 'የይለፍ ቃል ተቀይሯል' });
    } catch (err) {
        res.status(500).json({ error: 'Server Error' });
    }
});

app.put('/api/change-password', verifyToken, async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        const user = await User.findById(req.user.id);
        if (!user || !(await bcrypt.compare(oldPassword, user.password))) {
            return res.status(400).json({ error: 'የድሮው የይለፍ ቃል ስህተት ነው!' });
        }
        user.password = await bcrypt.hash(newPassword, 10);
        await user.save();
        res.json({ message: 'የይለፍ ቃል ተቀይሯል' });
    } catch (err) {
        res.status(500).json({ error: 'Server Error' });
    }
});

// --- Report Routes ---
app.post('/api/reports', verifyToken, upload.fields([{ name: 'photo' }, { name: 'video' }]), async (req, res) => {
    try {
        const reportData = { ...req.body, createdBy: req.user.username };
        if (req.user.role === 'user') reportData.zone = req.user.username;
        if (req.files?.photo) reportData.photoUrl = '/uploads/' + req.files.photo[0].filename;
        if (req.files?.video) reportData.videoUrl = '/uploads/' + req.files.video[0].filename;
        
        const report = await Report.create(reportData);
        res.status(201).json(report);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/reports', verifyToken, async (req, res) => {
    try {
        let query = {};
        if (req.user.role === 'user') {
            query.zone = req.user.username;
        }
        const reports = await Report.find(query).sort({ createdAt: -1 });
        res.json(reports);
    } catch (err) {
        res.status(500).json({ error: 'Server Error' });
    }
});

app.delete('/api/reports/:id', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'superadmin' && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'ፈቃድ የለዎትም!' });
        }
        await Report.findByIdAndDelete(req.params.id);
        res.json({ message: 'ሪፖርቱ ተሰርዟል' });
    } catch (err) {
        res.status(500).json({ error: 'Server Error' });
    }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
