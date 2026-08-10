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
// በከፍተኛ ደህንነት (Production) ወቅት ይህንን በ environment variable (.env) ማስተዳደር አለብዎት
const JWT_SECRET = process.env.JWT_SECRET || 'tech_transfer_secret_key_2018';

// Middleware
app.use(express.json());
app.use(cors());
// የፋይል ማውጫን መከላከል
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
    diagnosis: String, // ከNumber ወደ String ተቀይሯል (ምክንያቱም ጽሁፍ ስለሚቀበል)
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
    limits: { fileSize: 10 * 1024 * 1024 } // የፋይል መጠን ገደብ (10MB)
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

// --- API Routes (ስልታዊ በሆነ መንገድ የተደራጁ) ---

// Login
app.post('/api/auth/login', async (req, res) => {
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

// --- Report Routes (የተቀሩትንም በዚህ መልክ ያደራጁ) ---
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

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
