const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();

app.use(express.json());

const JWT_SECRET = 'your_strong_jwt_secret_key_change_this';

// በቋሚነት የተዘጋጀ Super Admin (መጀመሪያ ሲነሳ የሚፈጠር)
let users = [
  {
    username: 'superadmin',
    // '123456' የሚለው የይለፍ ቃል Hash የተደረገበት (እንደ ፍላጎትዎ ቀይሩት)
    passwordHash: bcrypt.hashSync('superadmin123', 10),
    role: 'superadmin'
  }
];

let reports = [];

// Middleware: Token ማረጋገጫ
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'ቶከን አልተገኘም!' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'ቶከኑ ትክክለኛ አይደለም!' });
    req.user = user;
    next();
  });
}

// 1. የመግቢያ API (Login Router) - Role-Based Validation
app.post('/api/login', async (req, res) => {
  const { username, password, role } = req.body;

  // ተጠቃሚውን በስም እና በሚናው (Role) መፈለግ
  const user = users.find(u => u.username === username && u.role === role);
  
  if (!user) {
    return res.status(401).json({ error: 'የተጠቃሚ ስም ወይም ሚና (Role) አልተገኘም!' });
  }

  // የይለፍ ቃሉን ከብክሪፕት ጋር ማጣራት
  const isValid = await bcrypt.compare(password, user.passwordHash);
  if (!isValid) {
    return res.status(401).json({ error: 'የተሳሳተ የይለፍ ቃል ያስገቡ!' });
  }

  const token = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
  res.json({ token, role: user.role, username: user.username });
});

// 2. ተጠቃሚዎችን የማውጫ API (ለLogin Dropdown)
app.get('/api/users', (req, res) => {
  const { role } = req.query;
  let filtered = users;
  
  if (role) {
    filtered = users.filter(u => u.role === role);
  }
  
  // የይለፍ ቃሉን ሳይጨምር ስምና ሚናውን ብቻ መመለስ
  const safeUsers = filtered.map(u => ({ username: u.username, role: u.role }));
  res.json(safeUsers);
});

// 3. አዲስ አካውንት መፍጠሪያ (🔒 Super Admin ብቻ እንዲፈጥር የተከለከለ)
app.post('/api/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'superadmin') {
    return res.status(403).json({ error: 'አዲስ አካውንት መፍጠር የሚችለው Super Admin ብቻ ነው!' });
  }

  const { username, password, role } = req.body;

  if (!username || !password || !role) {
    return res.status(400).json({ error: 'እባክዎ ሙሉ መረጃ ያስገቡ!' });
  }

  if (role === 'superadmin') {
    return res.status(400).json({ error: 'ተጨማሪ Super Admin መፍጠር አይቻልም!' });
  }

  const existingUser = users.find(u => u.username === username);
  if (existingUser) {
    return res.status(400).json({ error: 'ይህ የተጠቃሚ ስም አስቀድሞ ተይዟል!' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({
    username,
    passwordHash: hashedPassword,
    role
  });

  res.json({ message: 'አካውንቱ በተሳካ ሁኔታ ተፈጥሯል!' });
});

// 4. ተጠቃሚ የማጥፊያ API (Super Admin ብቻ)
app.delete('/api/users/:username', authenticateToken, (req, res) => {
  if (req.user.role !== 'superadmin') {
    return res.status(403).json({ error: 'ይህንን ድርጊት መፈጸም የሚችለው Super Admin ብቻ ነው!' });
  }

  const { username } = req.params;
  if (username === 'superadmin') {
    return res.status(400).json({ error: 'Super Admin አካውንትን ማጥፋት አይቻልም!' });
  }

  users = users.filter(u => u.username !== username);
  res.json({ message: 'ተጠቃሚው ተሰርዟል!' });
});

// 5. የሱፐር አድሚን ይለፍ ቃል መቀየሪያ API
app.post('/api/superadmin/change-password', authenticateToken, async (req, res) => {
  if (req.user.role !== 'superadmin') {
    return res.status(403).json({ error: 'ፈቃድ የለዎትም!' });
  }

  const { currentPassword, newPassword } = req.body;
  const superUser = users.find(u => u.username === 'superadmin');

  const isValid = await bcrypt.compare(currentPassword, superUser.passwordHash);
  if (!isValid) {
    return res.status(400).json({ error: 'የነበረው የይለፍ ቃል የተሳሳተ ነው!' });
  }

  superUser.passwordHash = await bcrypt.hash(newPassword, 10);
  res.json({ message: 'የይለፍ ቃሉ ተቀይሯል!' });
});

// 6. Report APIs
app.get('/api/report', authenticateToken, (req, res) => {
  res.json(reports);
});

app.post('/api/report', authenticateToken, (req, res) => {
  const newReport = { id: Date.now(), ...req.body, enteredBy: req.user.username };
  reports.push(newReport);
  res.json({ message: 'መረጃው ተመዝግቧል!' });
});

app.delete('/api/report/:id', authenticateToken, (req, res) => {
  if (req.user.role === 'admin') {
    return res.status(403).json({ error: 'መደበኛ Admin መረጃ ማጥፋት አይችልም!' });
  }
  reports = reports.filter(r => r.id !== parseInt(req.params.id));
  res.json({ message: 'መረጃው ተሰርዟል!' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
