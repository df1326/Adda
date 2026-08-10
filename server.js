const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = 'tech_transfer_secret_key_2018';

// Middleware
app.use(express.json());
app.use(cors());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Serve Frontend static files if needed
app.use(express.static(path.join(__dirname)));

// Ensure upload directory exists
if (!fs.existsSync('./uploads')) {
    fs.mkdirSync('./uploads');
}

// MongoDB Connection (Render ላይ ከኦንላይን MongoDB Atlas ጋር ለመገናኘት process.env.MONGO_URI እንጠቀማለን፣ካልተሰጠ በሎካል ይገናኛል)
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/tech_transfer_db';

mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('MongoDB Connected Successfully.'))
  .catch(err => console.log('MongoDB Connection Error:', err));

// --- Schemas & Models ---
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin', 'superadmin'], default: 'user' }
});
const User = mongoose.model('User', UserSchema);

const ReportSchema = new mongoose.Schema({
    zone: String,
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
    b_ent: Number,
    b_mobile: Number,
    b_male: Number,
    b_female: Number,
    diagnosis: Number,
    photoUrl: String,
    videoUrl: String,
    createdBy: String,
    createdAt: { type: Date, default: Date.now }
});
const Report = mongoose.model('Report', ReportSchema);

// Multer Storage Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, './uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage: storage });

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
            console.log('Superadmin created (username: superadmin, password: admin123)');
        }
    } catch (err) {
        console.log('Superadmin creation check error:', err.message);
    }
}
createSuperadmin();

// --- API Routes ---

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ error: 'ተጠቃሚው አልተገኘም!' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: 'የይለፍ ቃል ስህተት ነው!' });

        const token = jwt.sign({ id: user._id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1d' });
        res.json({ token, role: user.role, username: user.username });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get Current User
app.get('/api/me', verifyToken, async (req, res) => {
    res.json(req.user);
});

// Get Users (Superadmin only)
app.get('/api/users', verifyToken, async (req, res) => {
    if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'ፈቃድ የለዎትም!' });
    const users = await User.find({}, '-password');
    res.json(users);
});

// Create User (Superadmin only)
app.post('/api/users', verifyToken, async (req, res) => {
    if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'ፈቃድ የለዎትም!' });
    try {
        const { username, password, role } = req.body;
        const existing = await User.findOne({ username });
        if (existing) return res.status(400).json({ error: 'ይህ የተጠቃሚ ስም ቀደም ሲል አለ!' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await User.create({ username, password: hashedPassword, role });
        res.status(201).json({ message: 'ተጠቃሚው ተፈጥሯል!', id: newUser._id });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete User
app.delete('/api/users/:id', verifyToken, async (req, res) => {
    if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'ፈቃድ የለዎትም!' });
    await User.findByIdAndDelete(req.params.id);
    res.json({ message: 'ተሰርዟል!' });
});

// Reset Password
app.put('/api/users/reset-password/:id', verifyToken, async (req, res) => {
    if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'ፈቃድ የለዎትም!' });
    const hashedPassword = await bcrypt.hash(req.body.newPassword, 10);
    await User.findByIdAndUpdate(req.params.id, { password: hashedPassword });
    res.json({ message: 'የይለፍ ቃል ተቀይሯል!' });
});

// Get Reports
app.get('/api/reports', verifyToken, async (req, res) => {
    try {
        let reports;
        if (req.user.role === 'user') {
            reports = await Report.find({ zone: req.user.username });
        } else {
            reports = await Report.find({});
        }
        res.json(reports);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Create Report
app.post('/api/reports', verifyToken, upload.fields([{ name: 'photo' }, { name: 'video' }]), async (req, res) => {
    try {
        const data = req.body;
        if (req.user.role === 'user') {
            data.zone = req.user.username;
        }
        data.createdBy = req.user.username;

        if (req.files && req.files['photo']) data.photoUrl = '/uploads/' + req.files['photo'][0].filename;
        if (req.files && req.files['video']) data.videoUrl = '/uploads/' + req.files['video'][0].filename;

        const report = await Report.create(data);
        res.status(201).json(report);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update Report
app.put('/api/reports/:id', verifyToken, upload.fields([{ name: 'photo' }, { name: 'video' }]), async (req, res) => {
    try {
        const reportId = req.params.id;
        const existingReport = await Report.findById(reportId);
        if (!existingReport) return res.status(404).json({ error: 'ሪፖርቱ አልተገኘም!' });

        if (req.user.role === 'user' && existingReport.createdBy !== req.user.username) {
            return res.status(403).json({ error: 'ይህንን ሪፖርት ለማስተካከል ፈቃድ የለዎትም!' });
        }

        const updateData = { ...req.body };

        if (req.files && req.files['photo']) {
            updateData.photoUrl = '/uploads/' + req.files['photo'][0].filename;
        }
        if (req.files && req.files['video']) {
            updateData.videoUrl = '/uploads/' + req.files['video'][0].filename;
        }

        const updatedReport = await Report.findByIdAndUpdate(reportId, updateData, { new: true });
        res.json(updatedReport);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete Report
app.delete('/api/reports/:id', verifyToken, async (req, res) => {
    try {
        const report = await Report.findById(req.params.id);
        if (!report) return res.status(404).json({ error: 'ሪፖርቱ አልተገኘም!' });

        if (req.user.role === 'user' && report.createdBy !== req.user.username) {
            return res.status(403).json({ error: 'ይህንን ሪፖርት ለመሰረዝ ፈቃድ የለዎትም!' });
        }

        await Report.findByIdAndDelete(req.params.id);
        res.json({ message: 'ተሰርዟል!' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Fallback to index.html for SPA routing
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
