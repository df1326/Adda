const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const path = require('path');
const helmet = require('helmet');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');

const app = express();

// 1. Cloudinary Setup
cloudinary.config({
    cloud_name: 'tdrscp1g',
    api_key: '985967155381663',
    api_secret: '9vi1YGKgSLQUugzOrsp-liO7FEU'
});

// Multer Memory Storage for handling file uploads before sending to Cloudinary
const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: { fileSize: 50 * 1024 * 1024 } // እስከ 50MB ፋይል (ፎቶ/ቪዲዮ) እንዲጫን የተፈቀደ
});

// 2. Security Headers & CORS
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ---------------- Static Files ----------------
app.use(express.static(path.join(__dirname, 'public'))); 

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_tech_transfer_key_2026';
const MONGODB_URI = process.env.MONGODB_URI || "mongodb+srv://addisutsigie16_db_user:0q7UA21Lq8s0bdXZ@cluster0.dzl7lt9.mongodb.net/tech_transfer_db?retryWrites=true&w=majority";

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
    transferQty: String,
    transferSector: String,
    resource: String,
    b_ent: String,
    b_mobile: String,
    b_male: String,
    b_female: String,
    diagnosis: String,
    photoUrl: String, 
    videoUrl: String, 
    createdBy: String,
    created_at: { type: Date, default: Date.now }
});

const User = mongoose.models.User || mongoose.model('User', userSchema);
const Report = mongoose.models.Report || mongoose.model('Report', reportSchema);

// ---------------- Superadmin Auto Init ----------------
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
            console.log('✅ Default superadmin created (username: superadmin / password: admin123)');
        }
    } catch (err) {
        console.error('❌ Superadmin init error:', err.message);
    }
};

// MongoDB Connection
mongoose.connect(MONGODB_URI)
    .then(() => {
        console.log('⚡ Connected to MongoDB Atlas successfully!');
        initSuperadmin();
    })
    .catch(err => {
        console.error('❌ MongoDB Connection Error:', err);
        process.exit(1);
    });

// Auth Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'ያልተፈቀደ መግቢያ! እባክዎ መጀመሪያ ይግቡ።' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'የሴሽን ጊዜዎ አልፎአል!' });
        req.user = user;
        next();
    });
};

// Helper function to upload buffer to Cloudinary
const uploadToCloudinary = (buffer, resourceType = 'image') => {
    return new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
            { resource_type: resourceType },
            (error, result) => {
                if (error) reject(error);
                else resolve(result);
            }
        );
        uploadStream.end(buffer);
    });
};

// ==================== API ROUTES ====================

app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'Server is running with full permissions & multi-color support!' });
});

app.get('/api/me', authenticateToken, (req, res) => {
    res.json({ username: req.user.username, role: req.user.role });
});

app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        if (!username || !password) {
            return res.status(400).json({ error: 'እባክዎ የተጠቃሚ ስም እና የይለፍ ቃል ያስገቡ!' });
        }
        const user = await User.findOne({ username: username.trim() });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ error: 'የተጠቃሚ ስም ወይም የይለፍ ቃል ስህተት ነው!' });
        }
        const token = jwt.sign({ id: user._id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '12h' });
        res.json({ message: 'በተሳካ ሁኔታ ገብተዋል', token, role: user.role, username: user.username });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'የሰርቨር ስህተት ተከሰቷል!' });
    }
});

// User Management Routes (Superadmin Only Permissions)
app.get('/api/users', authenticateToken, async (req, res) => {
    try {
        const users = await User.find({}, '-password');
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: 'መረጃዎችን ማምጣት አልተቻለም!' });
    }
});

app.post('/api/users', authenticateToken, async (req, res) => {
    if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'ይህንን ተግባር ለማከናወን የሱፐር አድሚን ፈቃድ ያስፈልግዎታል!' });
    const { username, password, role } = req.body;
    try {
        if (!username || !password || !role) {
            return res.status(400).json({ error: 'እባክዎ ሁሉንም መስኮች ይሙሉ!' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await User.create({ username: username.trim(), password: hashedPassword, role });
        res.json({ message: 'አዲስ ተጠቃሚ በተሳካ ሁኔታ ተፈጥሯል!', user: { id: newUser._id, username, role } });
    } catch (err) {
        res.status(400).json({ error: 'የተጠቃሚ ስም ቀደም ሲል ተይዟል!' });
    }
});

app.delete('/api/users/:username', authenticateToken, async (req, res) => {
    if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'ይህንን ተግባር ለማከናወን የሱፐር አድሚን ፈቃድ ያስፈልግዎታል!' });
    try {
        if (req.params.username === 'superadmin') {
            return res.status(400).json({ error: 'ዋናውን ሱፐር አድሚን መሰረዝ አይቻልም!' });
        }
        await User.findOneAndDelete({ username: req.params.username });
        res.json({ message: 'ተጠቃሚው በተሳካ ሁኔታ ተሰርዟል!' });
    } catch (err) {
        res.status(500).json({ error: 'ተጠቃሚውን ማጥፋት አልተቻለም!' });
    }
});

app.put('/api/users/:username/password', authenticateToken, async (req, res) => {
    if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'ይህንን ተግባር ለማከናወን የሱፐር አድሚን ፈቃድ ያስፈልግዎታል!' });
    try {
        const { password } = req.body;
        if (!password) return res.status(400).json({ error: 'አዲስ የይለፍ ቃል ያስገቡ!' });
        const hashedPassword = await bcrypt.hash(password.trim(), 10);
        await User.findOneAndUpdate({ username: req.params.username }, { password: hashedPassword });
        res.json({ message: 'የተጠቃሚው የይለፍ ቃል ተቀይሯል!' });
    } catch (err) {
        res.status(500).json({ error: 'የይለፍ ቃል መቀየር አልተቻለም!' });
    }
});

app.put('/api/password', authenticateToken, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    try {
        const user = await User.findById(req.user.id);
        if (!user || !(await bcrypt.compare(oldPassword, user.password))) {
            return res.status(400).json({ error: 'የድሮው የይለፍ ቃል ልክ አይደለም!' });
        }
        user.password = await bcrypt.hash(newPassword.trim(), 10);
        await user.save();
        res.json({ message: 'የይለፍ ቃልዎ በተሳካ ሁኔታ ተቀይሯል!' });
    } catch (err) {
        res.status(500).json({ error: 'መቀየር አልተቻለም!' });
    }
});

// ---------------- Reports API ----------------
app.post('/api/reports', authenticateToken, upload.fields([
    { name: 'photo', maxCount: 1 },
    { name: 'video', maxCount: 1 }
]), async (req, res) => {
    try {
        let photoUrl = '';
        let videoUrl = '';

        if (req.files && req.files.photo) {
            const photoRes = await uploadToCloudinary(req.files.photo[0].buffer, 'image');
            photoUrl = photoRes.secure_url;
        }

        if (req.files && req.files.video) {
            const videoRes = await uploadToCloudinary(req.files.video[0].buffer, 'video');
            videoUrl = videoRes.secure_url;
        }

        const newReport = await Report.create({
            ...req.body,
            photoUrl: photoUrl,
            videoUrl: videoUrl,
            createdBy: req.user.username
        });

        res.json({ message: 'ሪፖርቱ እና ፋይሎቹ በተሳካ ሁኔታ ተመዝግበዋል!', id: newReport._id });
    } catch (err) {
        console.error('Upload Error:', err);
        res.status(500).json({ error: 'ፋይል ወይም ሪፖርት መመዝገብ አልተቻለም!' });
    }
});

app.get('/api/reports', authenticateToken, async (req, res) => {
    try {
        const reports = await Report.find().sort({ created_at: -1 });
        res.json(reports);
    } catch (err) {
        res.status(500).json({ error: 'ሪፖርቶችን ማምጣት አልተቻለም!' });
    }
});

app.delete('/api/reports/:id', authenticateToken, async (req, res) => {
    try {
        await Report.findByIdAndDelete(req.params.id);
        res.json({ message: 'ሪፖርቱ ተሰርዟል!' });
    } catch (err) {
        res.status(500).json({ error: 'መሰረዝ አልተቻለም!' });
    }
});

// Error handling
app.use((err, req, res, next) => {
    console.error('❌ Server Error:', err.stack);
    res.status(500).json({ error: 'ያልተጠበቀ ስህተት አጋጥሟል!' });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
