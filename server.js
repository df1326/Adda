const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const path = require('path');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');

const app = express();

// 1. የ HTTP የደህንነት ሄደሮች (Security Headers) በ Helmet ማካተት
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

// CORS ማዋቀር
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// ---------------- Static Files & Root Route Setup ----------------
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
        } else {
            console.log('ℹ️ Superadmin account is ready in MongoDB Atlas.');
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
        if (err) return res.status(403).json({ error: 'የሴሽን ጊዜዎ አልፎአል ወይም የተሳሳተ ቶከን ነው!' });
        req.user = user;
        next();
    });
};

// ==================== API ROUTES ====================

// 1. Health Check
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'Render Node.js Server is running smoothly!' });
});

// 2. Currently Logged in User Details (/api/me)
app.get('/api/me', authenticateToken, (req, res) => {
    res.json({
        username: req.user.username,
        role: req.user.role
    });
});

// 3. Explicit Superadmin Init Endpoint
app.post('/api/init-superadmin', async (req, res) => {
    await initSuperadmin();
    res.json({ message: 'Superadmin check/initialization completed!' });
});

// 4. Login Endpoint
app.post('/api/login', [
    body('username').notEmpty().withMessage('የተጠቃሚ ስም ባዶ መሆን አይችልም!'),
    body('password').notEmpty().withMessage('የይለፍ ቃል ባዶ መሆን አይችልም!')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array()[0].msg });
    }

    const { username, password, role } = req.body;

    try {
        const query = role ? { username: username.trim(), role: role.trim() } : { username: username.trim() };
        const user = await User.findOne(query);

        if (!user) {
            return res.status(400).json({ error: 'የተጠቃሚው ስም ወይም ሚና አልተገኘም! እባክዎ በትክክል መመረጡን ያረጋግጡ።' });
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

// 5. Change Password
app.post('/api/change-password', authenticateToken, [
    body('oldPassword').notEmpty(),
    body('newPassword').isLength({ min: 6 }).withMessage('አዲሱ የይለፍ ቃል ቢያንስ 6 ሆሄያት ሊኖሩት ይገባል!')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array()[0].msg });
    }

    const { oldPassword, newPassword } = req.body;

    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ error: 'ተጠቃሚው አልተገኘም!' });

        const validPassword = await bcrypt.compare(oldPassword, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'የድሮው የይለፍ ቃል የተሳሳተ ነው!' });
        }

        user.password = await bcrypt.hash(newPassword, 10);
        await user.save();

        res.json({ message: 'የይለፍ ቃልዎ በተሳካ ሁኔታ ተቀይሯል!' });
    } catch (err) {
        res.status(500).json({ error: 'የይለፍ ቃል መቀየር አልተቻለም!' });
    }
});

// 6. Admin Reset Password
app.post('/api/admin/reset-password', authenticateToken, async (req, res) => {
    if (req.user.role !== 'superadmin' && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'ፈቃድ የለዎትም!' });
    }

    const { username, newPassword } = req.body;
    if (!username || !newPassword) {
        return res.status(400).json({ error: 'እባክዎ የተጠቃሚ ስም እና አዲስ የይለፍ ቃል ያስገቡ!' });
    }

    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        const updatedUser = await User.findOneAndUpdate(
            { username: username.trim() },
            { password: hashedPassword },
            { new: true }
        );

        if (!updatedUser) {
            return res.status(404).json({ error: 'ተጠቃሚው በዳታቤዝ ውስጥ አልተገኘም!' });
        }

        res.json({ message: 'የተጠቃሚው ፓስዋርድ በተሳካ ሁኔታ ተቀይሯል!' });
    } catch (err) {
        res.status(500).json({ error: 'ሰርቨር ላይ ስህተት ተፈጥሯል!' });
    }
});

// 7. Manage Users
app.get('/api/users', authenticateToken, async (req, res) => {
    try {
        const users = await User.find({}, '-password');
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: 'መረጃዎችን ማምጣት አልተቻለም!' });
    }
});

app.post('/api/users', authenticateToken, [
    body('username').notEmpty().trim(),
    body('password').isLength({ min: 6 }),
    body('role').isIn(['superadmin', 'admin', 'user'])
], async (req, res) => {
    if (req.user.role !== 'superadmin') {
        return res.status(403).json({ error: 'ፈቃድ የለዎትም!' });
    }
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'ያስገቡት መረጃ የተሳሳተ ወይም ያልተሟላ ነው!' });
    }

    const { username, password, role } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await User.create({ username: username.trim(), password: hashedPassword, role });
        res.json({ message: 'ተጠቃሚ ተፈጥሯል!', user: { id: newUser._id, username, role } });
    } catch (err) {
        res.status(400).json({ error: 'የተጠቃሚ ስም ቀደም ሲል ተይዟል!' });
    }
});

app.delete('/api/users/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'superadmin') {
        return res.status(403).json({ error: 'ተጠቃሚዎችን የመሰረዝ መብት ያለው Super Admin ብቻ ነው!' });
    }
    try {
        const targetUser = await User.findById(req.params.id);
        if (targetUser && targetUser.role === 'superadmin') {
            return res.status(400).json({ error: 'ዋናውን Super Admin ማጥፋት አይቻልም!' });
        }
        await User.findByIdAndDelete(req.params.id);
        res.json({ message: 'ተጠቃሚው በተሳካ ሁኔታ ተሰርዟል!' });
    } catch (err) {
        res.status(500).json({ error: 'መሰረዝ አልተቻለም!' });
    }
});

// 8. Reports API
app.post('/api/report', authenticateToken, async (req, res) => {
    try {
        const newReport = await Report.create({ ...req.body, createdBy: req.user.username });
        res.json({ message: 'ሪፖርቱ ተመዝግቧል!', id: newReport._id });
    } catch (err) {
        res.status(500).json({ error: 'ሪፖርት መመዝገብ አልተቻለም!' });
    }
});

app.get('/api/report', authenticateToken, async (req, res) => {
    try {
        const reports = await Report.find().sort({ created_at: -1 });
        res.json(reports);
    } catch (err) {
        res.status(500).json({ error: 'ሪፖርቶችን ማምጣት አልተቻለም!' });
    }
});

app.delete('/api/report/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'superadmin' && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'ሪፖርት የማጥፋት መብት የለዎትም!' });
    }
    try {
        await Report.findByIdAndDelete(req.params.id);
        res.json({ message: 'ሪፖርቱ በተሳካ ሁኔታ ተሰርዟል!' });
    } catch (err) {
        res.status(500).json({ error: 'ሪፖርቱን መሰረዝ አልተቻለም!' });
    }
});

// ==================== ERROR HANDLING ====================
app.use('/api/*', (req, res) => {
    res.status(404).json({ success: false, error: 'የጠየቁት የ API አድራሻ (Route) አልተገኘም!' });
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((err, req, res, next) => {
    console.error('❌ Internal Server Error:', err.stack);
    res.status(500).json({ success: false, error: 'በሰርቨር ላይ ያልተጠበቀ ስህተት አጋጥሟል!' });
});

// Start Server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
