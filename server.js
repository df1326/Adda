const express = require('express');
const cors = require('cors');
const path = require('path');
const app = express();

app.use(cors());
app.use(express.json());

// HTML እና ሌሎች Static ፋይሎችን ለማስተናገድ
app.use(express.static(path.join(__dirname)));

// ጊዜያዊ የዳታ ማስቀመጫ
let reports = [];
let users = [
  { username: 'user1', role: 'user' },
  { username: 'admin1', role: 'admin' }
];

// 1. የተጠቃሚዎች ዝርዝር ለማምጣት
app.get('/api/users', (req, res) => {
    const role = req.query.role;
    if (role) {
        return res.json(users.filter(u => u.role === role));
    }
    res.json(users);
});

// 2. የመግቢያ (Login) ኤንድፖይንት
app.post('/api/login', (req, res) => {
    const { username, password, role } = req.body;
    res.json({ token: 'sample-jwt-token', role: role });
});

// 3. አዲስ ሪፖርት ለመመዝገብ (POST)
app.post('/api/report', (req, res) => {
    const newReport = { id: Date.now(), ...req.body, enteredBy: 'ባለሙያ' };
    reports.push(newReport);
    res.status(201).json({ message: 'ተመዝግቧል', data: newReport });
});

// 4. የተቀመጡ ሪፖርቶችን ለማየት (GET)
app.get('/api/report', (req, res) => {
    res.json(reports);
});

// 5. ሪፖርት ለማጥፋት (DELETE)
app.delete('/api/report/:id', (req, res) => {
    const id = parseInt(req.params.id);
    reports = reports.filter(r => r.id !== id);
    res.json({ message: 'ተሰርዟል' });
});

// 6. ማንኛውም ተጠቃሚ በሊንኩ ሲገባ በቀጥታ index.html እንዲከፈትለት
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Render በራሱ Port ይመድባል፤ ከሌለ ነባሪ 3000 ይጠቀማል
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
