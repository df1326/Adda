const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const app = express();

// CORS ን ማንቃት
app.use(cors());
app.use(express.json());

// Static files ን ማገልገል - ትክክለኛውን መንገድ መጠቀም
const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));

const JWT_SECRET = process.env.JWT_SECRET || 'your_strong_jwt_secret_key_change_this_in_production';

// በቋሚነት የተዘጋጀ Super Admin
let users = [
  {
    username: 'superadmin',
    passwordHash: bcrypt.hashSync('admin123', 10),
    role: 'superadmin'
  }
];

let reports = [];

// ============================================================
// Middleware: Token ማረጋገጫ
// ============================================================
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

// ============================================================
// 1. የመግቢያ API
// ============================================================
app.post('/api/login', async (req, res) => {
  try {
    const { username, password, role } = req.body;

    const user = users.find(u => u.username === username && u.role === role);
    
    if (!user) {
      return res.status(401).json({ error: 'የተጠቃሚ ስም ወይም ሚና አልተገኘም!' });
    }

    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) {
      return res.status(401).json({ error: 'የተሳሳተ የይለፍ ቃል!' });
    }

    const token = jwt.sign(
      { username: user.username, role: user.role }, 
      JWT_SECRET, 
      { expiresIn: '8h' }
    );
    res.json({ token, role: user.role, username: user.username });
  } catch (error) {
    res.status(500).json({ error: 'ስህተት ተከሰተ!' });
  }
});

// ============================================================
// 2. ሱፐር አድሚን ማስጀመሪያ
// ============================================================
app.post('/api/init-superadmin', async (req, res) => {
  try {
    const existing = users.find(u => u.username === 'superadmin');
    if (!existing) {
      users.push({
        username: 'superadmin',
        passwordHash: await bcrypt.hash('admin123', 10),
        role: 'superadmin'
      });
      res.json({ message: 'ሱፐር አድሚን ተፈጥሯል!' });
    } else {
      res.json({ message: 'ሱፐር አድሚን አስቀድሞ አለ!' });
    }
  } catch (error) {
    res.status(500).json({ error: 'ሱፐር አድሚን መፍጠር አልተቻለም!' });
  }
});

// ============================================================
// 3. ተጠቃሚዎችን ማውጣት
// ============================================================
app.get('/api/users', (req, res) => {
  try {
    const { role } = req.query;
    let filtered = users;
    
    if (role) {
      filtered = users.filter(u => u.role === role);
    }
    
    const safeUsers = filtered.map(u => ({ username: u.username, role: u.role }));
    res.json(safeUsers);
  } catch (error) {
    res.status(500).json({ error: 'ተጠቃሚዎችን ማውጣት አልተቻለም!' });
  }
});

// ============================================================
// 4. አዲስ አካውንት መፍጠር (Super Admin ብቻ)
// ============================================================
app.post('/api/users', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'superadmin') {
      return res.status(403).json({ error: 'Super Admin ብቻ አዲስ አካውንት መፍጠር ይችላል!' });
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
      return res.status(400).json({ error: 'ይህ ስም አስቀድሞ ተይዟል!' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'የይለፍ ቃል ቢያንስ 6 ቁምፊ መሆን አለበት!' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, passwordHash: hashedPassword, role });

    res.json({ 
      message: `አዲስ ${role === 'admin' ? 'አድሚን' : 'ተጠቃሚ'} '${username}' ተፈጥሯል!` 
    });
  } catch (error) {
    res.status(500).json({ error: 'ተጠቃሚ መፍጠር አልተቻለም!' });
  }
});

// ============================================================
// 5. ተጠቃሚ መሰረዝ (Super Admin ብቻ)
// ============================================================
app.delete('/api/users/:username', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'superadmin') {
      return res.status(403).json({ error: 'Super Admin ብቻ ተጠቃሚ መሰረዝ ይችላል!' });
    }

    const { username } = req.params;
    if (username === 'superadmin') {
      return res.status(400).json({ error: 'Super Admin አካውንትን ማጥፋት አይቻልም!' });
    }

    const userExists = users.find(u => u.username === username);
    if (!userExists) {
      return res.status(404).json({ error: 'ተጠቃሚው አልተገኘም!' });
    }

    users = users.filter(u => u.username !== username);
    res.json({ message: `ተጠቃሚ '${username}' ተሰርዟል!` });
  } catch (error) {
    res.status(500).json({ error: 'ተጠቃሚ መሰረዝ አልተቻለም!' });
  }
});

// ============================================================
// 6. ሱፐር አድሚን ፓስዎርድ መቀየር
// ============================================================
app.post('/api/superadmin/change-password', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'superadmin') {
      return res.status(403).json({ error: 'Super Admin ብቻ ይህን ማድረግ ይችላል!' });
    }

    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'ሁለቱንም የይለፍ ቃላት ያስገቡ!' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'አዲሱ የይለፍ ቃል ቢያንስ 6 ቁምፊ መሆን አለበት!' });
    }

    const superUser = users.find(u => u.username === 'superadmin');
    if (!superUser) {
      return res.status(404).json({ error: 'ሱፐር አድሚን አልተገኘም!' });
    }

    const isValid = await bcrypt.compare(currentPassword, superUser.passwordHash);
    if (!isValid) {
      return res.status(400).json({ error: 'የነበረው የይለፍ ቃል የተሳሳተ ነው!' });
    }

    superUser.passwordHash = await bcrypt.hash(newPassword, 10);
    res.json({ message: 'የይለፍ ቃል ተቀይሯል!' });
  } catch (error) {
    res.status(500).json({ error: 'የይለፍ ቃል መቀየር አልተቻለም!' });
  }
});

// ============================================================
// 7. Report APIs
// ============================================================
app.get('/api/report', authenticateToken, (req, res) => {
  try {
    res.json(reports);
  } catch (error) {
    res.status(500).json({ error: 'ሪፖርቶችን ማውጣት አልተቻለም!' });
  }
});

app.post('/api/report', authenticateToken, (req, res) => {
  try {
    if (req.user.role === 'superadmin' || req.user.role === 'admin') {
      return res.status(403).json({ error: 'ሪፖርት መሙላት የሚችለው ተጠቃሚ ብቻ ነው!' });
    }

    const newReport = { 
      id: Date.now(), 
      ...req.body, 
      enteredBy: req.user.username 
    };
    reports.push(newReport);
    res.json({ message: 'መረጃው ተመዝግቧል!' });
  } catch (error) {
    res.status(500).json({ error: 'ሪፖርት መዝገብ አልተቻለም!' });
  }
});

app.delete('/api/report/:id', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'superadmin') {
      return res.status(403).json({ error: 'Super Admin ብቻ ሪፖርት መሰረዝ ይችላል!' });
    }

    const reportId = parseInt(req.params.id);
    const reportExists = reports.find(r => r.id === reportId);
    
    if (!reportExists) {
      return res.status(404).json({ error: 'ሪፖርቱ አልተገኘም!' });
    }

    reports = reports.filter(r => r.id !== reportId);
    res.json({ message: 'ሪፖርቱ ተሰርዟል!' });
  } catch (error) {
    res.status(500).json({ error: 'ሪፖርት መሰረዝ አልተቻለም!' });
  }
});

// ============================================================
// 8. የፊትኤንድ ፋይሎችን ማገልገል - ማንኛውንም መንገድ ወደ index.html መላክ
// ============================================================
// ሁሉንም ያልተወሰኑ መንገዶች ወደ index.html መላክ (SPA ለመስራት)
app.get('*', (req, res) => {
  res.sendFile(path.join(publicPath, 'index.html'));
});

// ============================================================
// 9. ሰርቨሩን ማስጀመር
// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('='.repeat(50));
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`✅ Default Super Admin:`);
  console.log(`   Username: superadmin`);
  console.log(`   Password: admin123`);
  console.log('='.repeat(50));
  console.log(`📁 Public path: ${publicPath}`);
  console.log('='.repeat(50));
});
