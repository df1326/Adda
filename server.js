const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_tech_transfer_key_2026';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database Setup (SQLite)
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.error('❌ Database connection failed:', err.message);
    } else {
        console.log('⚡ Connected to SQLite database.');
    }
});

// Create Tables
db.serialize(() => {
    // Users Table
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('superadmin', 'admin', 'user')),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Reports Table
    db.run(`
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            zone TEXT,
            poly TEXT,
            techName TEXT,
            coordinator TEXT,
            phone TEXT,
            sector TEXT,
            valueChain TEXT,
            techType TEXT,
            year TEXT,
            transferQty INTEGER,
            transferSector TEXT,
            resource REAL,
            b_ent INTEGER,
            b_mobile INTEGER,
            b_male INTEGER,
            b_female INTEGER,
            diagnosis INTEGER,
            createdBy TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
});

// Middleware for Token Verification
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

// ==================== ROUTES / API ENDPOINTS ====================

// 1. Initialize Super Admin (ካልኖረ ብቻ ለመፍጠር)
app.post('/api/init-superadmin', async (req, res) => {
    try {
        db.get(`SELECT * FROM users WHERE role = 'superadmin'`, async (err, row) => {
            if (err) return res.status(500).json({ error: err.message });
            if (!row) {
                const hashedPassword = await bcrypt.hash('admin123', 10);
                db.run(
                    `INSERT INTO users (username, password, role) VALUES (?, ?, ?)`,
                    ['superadmin', hashedPassword, 'superadmin'],
                    function (err) {
                        if (err) return res.status(500).json({ error: err.message });
                        return res.json({ message: 'Default superadmin created (superadmin / admin123)' });
                    }
                );
            } else {
                return res.json({ message: 'Superadmin already exists.' });
            }
        });
    } catch (e) {
        res.status(500).json({ error: 'Server error' });
    }
});

// 2. Login Endpoint
app.post('/api/login', (req, res) => {
    const { username, password, role } = req.body;

    if (!username || !password || !role) {
        return res.status(400).json({ error: 'እባክዎ ሁሉንም መስኮች ይሙሉ!' });
    }

    db.get(`SELECT * FROM users WHERE username = ? AND role = ?`, [username, role], async (err, user) => {
        if (err) return res.status(500).json({ error: 'የዳታቤዝ ስህተት!' });
        if (!user) return res.status(400).json({ error: 'የተጠቃሚው ስም ወይም ሚና አልተገኘም!' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'የተሳሳተ የይለፍ ቃል!' });

        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '8h' }
        );

        res.json({
            message: 'በተሳካ ሁኔታ ገብተዋል',
            token: token,
            role: user.role,
            username: user.username
        });
    });
});

// 3. Fetch Users (በሚና መሰረት ወይም በሙሉ)
app.get('/api/users', (req, res) => {
    const { role } = req.query;
    let query = `SELECT id, username, role, created_at FROM users`;
    let params = [];

    if (role) {
        query += ` WHERE role = ?`;
        params.push(role);
    }

    db.all(query, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// 4. Create New User (Super Admin ብቻ)
app.post('/api/users', authenticateToken, async (req, res) => {
    if (req.user.role !== 'superadmin') {
        return res.status(403).json({ error: 'አዲስ ተጠቃሚ የመፍጠር 권한 የለዎትም!' });
    }

    const { username, password, role } = req.body;

    if (!username || !password || !role) {
        return res.status(400).json({ error: 'እባክዎ ሁሉንም መረጃዎች ያስገቡ!' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(
            `INSERT INTO users (username, password, role) VALUES (?, ?, ?)`,
            [username, hashedPassword, role],
            function (err) {
                if (err) {
                    if (err.message.includes('UNIQUE')) {
                        return res.status(400).json({ error: 'ይህ የተጠቃሚ ስም አስቀድሞ ተይዟል!' });
                    }
                    return res.status(500).json({ error: err.message });
                }
                res.json({ message: 'አዲስ ተጠቃሚ በተሳካ ሁኔታ ተፈጥሯል!', id: this.lastID });
            }
        );
    } catch (e) {
        res.status(500).json({ error: 'የይለፍ ቃል ማደራጀት አልተቻለም!' });
    }
});

// 5. Delete User (Super Admin ብቻ)
app.delete('/api/users/:username', authenticateToken, (req, res) => {
    if (req.user.role !== 'superadmin') {
        return res.status(403).json({ error: 'ተጠቃሚ የማጥፋት መብት የለዎትም!' });
    }

    const { username } = req.params;

    if (username === 'superadmin') {
        return res.status(400).json({ error: 'ዋናውን Super Admin ማጥፋት አይቻልም!' });
    }

    db.run(`DELETE FROM users WHERE username = ?`, [username], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'ተጠቃሚው በቋሚነት ተሰርዟል!' });
    });
});

// 6. Add Report (User ወይም Admin)
app.post('/api/report', authenticateToken, (req, res) => {
    const data = req.body;
    const createdBy = req.user.username;

    const query = `
        INSERT INTO reports (
            zone, poly, techName, coordinator, phone, sector, valueChain, 
            techType, year, transferQty, transferSector, resource, 
            b_ent, b_mobile, b_male, b_female, diagnosis, createdBy
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const params = [
        data.zone, data.poly, data.techName, data.coordinator, data.phone, data.sector,
        data.valueChain, data.techType, data.year, data.transferQty, data.transferSector,
        data.resource, data.b_ent, data.b_mobile, data.b_male, data.b_female,
        data.diagnosis, createdBy
    ];

    db.run(query, params, function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'ሪፖርቱ በተሳካ ሁኔታ ተመዝግቧል!', id: this.lastID });
    });
});

// 7. Get All Reports
app.get('/api/report', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM reports ORDER BY id DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// 8. Delete Report (Super Admin ብቻ)
app.delete('/api/report/:id', authenticateToken, (req, res) => {
    if (req.user.role !== 'superadmin') {
        return res.status(403).json({ error: 'ሪፖርት የማጥፋት መብት የለዎትም!' });
    }

    const { id } = req.params;

    db.run(`DELETE FROM reports WHERE id = ?`, [id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'ሪፖርቱ በተሳካ ሁኔታ ተሰርዟል!' });
    });
});

// 9. Fallback Route ለ SPA Frontend
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
