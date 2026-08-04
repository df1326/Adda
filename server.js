const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 10000;

// CORS ፈቃድ ለሁሉም Origins እና Headers መስጠት
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// በሜሞሪ ውስጥ የሚቀመጡ ጊዜያዊ ዳታዎች (ለሙከራ)
let users = [
    { username: 'superadmin', role: 'superadmin' },
    { username: 'አበበ', role: 'admin' },
    { username: 'ከበደ', role: 'user' },
    { username: 'አልማዝ', role: 'user' }
];

let reports = [];

// 1. የሰርቨር ጤንነት ማረጋገጫ (Health Check)
app.get('/', (req, res) => {
    res.json({ status: 'ok', message: 'Technology Transfer API is running smoothly' });
});

// 2. Superadmin የመጀመሪያ ስራ (Initialize Superadmin)
app.post('/api/init-superadmin', (req, res) => {
    const hasSuperAdmin = users.some(u => u.role === 'superadmin');
    if (!hasSuperAdmin) {
        users.push({ username: 'superadmin', role: 'superadmin' });
    }
    res.json({ message: 'Superadmin initialized successfully' });
});

// 3. የተጠቃሚዎች መግቢያ API (Login Endpoint)
app.post('/api/login', (req, res) => {
    const { username, password, role } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'እባክዎ የተጠቃሚ ስም እና የይለፍ ቃል ያስገቡ!' });
    }

    // ለጊዜው ለማረጋገጥ ቀላል ፓስወርድ
    if (password.length < 4) {
        return res.status(401).json({ error: 'የይለፍ ቃሉ የተሳሳተ ነው!' });
    }

    // Dummy JWT Token
    const token = 'mock-jwt-token-' + Date.now();
    res.json({
        message: 'በተሳካ ሁኔታ ገብተዋል',
        token: token,
        role: role || 'user',
        username: username
    });
});

// 4. የተጠቃሚዎችን ዝርዝር ማምጫ API (Get Users Endpoint)
app.get('/api/users', (req, res) => {
    const role = req.query.role;
    
    if (role && role !== 'superadmin') {
        const filteredUsers = users.filter(u => u.role === role);
        return res.json(filteredUsers);
    }
    
    res.json(users);
});

// 5. አዲስ ተጠቃሚ መፍጠሪያ API (Create User)
app.post('/api/users', (req, res) => {
    const { username, role } = req.body;
    if (!username) {
        return res.status(400).json({ error: 'የተጠቃሚ ስም አስፈላጊ ነው!' });
    }
    
    const newUser = { username, role: role || 'user' };
    users.push(newUser);
    res.status(201).json({ message: 'ተጠቃሚው ተፈጥሯል', user: newUser });
});

// 6. ተጠቃሚ ማጥፊያ API (Delete User)
app.delete('/api/users/:username', (req, res) => {
    const { username } = req.params;
    users = users.filter(u => u.username !== username);
    res.json({ message: 'ተጠቃሚው ተሰርዟል' });
});

// 7. የሪፖርት መዝገብ API (Reports Endpoints)
app.get('/api/report', (req, res) => {
    res.json(reports);
});

app.post('/api/report', (req, res) => {
    const reportData = req.body;
    reportData.id = Date.now();
    reportData.createdAt = new Date().toISOString();
    reports.push(reportData);
    res.status(201).json({ message: 'ሪፖርቱ ተመዝግቧል', report: reportData });
});

app.delete('/api/report/:id', (req, res) => {
    const id = parseInt(req.params.id);
    reports = reports.filter(r => r.id !== id);
    res.json({ message: 'ሪፖርቱ ተሰርዟል' });
});

// ሰርቨሩን ማስነሳት
app.listen(PORT, () => {
    console.log(`🚀 Server is listening on port ${PORT}`);
});
