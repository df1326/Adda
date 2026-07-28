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
    passwordHash: bcrypt.hashSync('admin123', 10),
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

// ============================================================
// 1. የመግቢያ API (Login Router) - Role-Based Validation
// ============================================================
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

// ============================================================
// 2. ሱፐር አድሚን ለማስጀመር (Initialization)
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
      res.json({ message: 'ሱፐር አድሚን በተሳካ ሁኔታ ተፈጥሯል!' });
    } else {
      res.json({ message: 'ሱፐር አድሚን አስቀድሞ አለ!' });
    }
  } catch (error) {
    res.status(500).json({ error: 'ሱፐር አድሚን መፍጠር አልተቻለም!' });
  }
});

// ============================================================
// 3. ተጠቃሚዎችን የማውጫ API (ለLogin Dropdown)
// ============================================================
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

// ============================================================
// 4. አዲስ አካውንት መፍጠሪያ (🔒 Super Admin ብቻ)
// ============================================================
app.post('/api/users', authenticateToken, async (req, res) => {
  console.log('📝 Creating user request received');
  console.log('👤 Current user:', req.user);
  console.log('📦 Request body:', req.body);

  // ሱፐር አድሚን ብቻ አዲስ አካውንት መፍጠር ይችላል
  if (req.user.role !== 'superadmin') {
    console.log('❌ User is not superadmin:', req.user.role);
    return res.status(403).json({ error: 'አዲስ አካውንት መፍጠር የሚችለው Super Admin ብቻ ነው!' });
  }

  const { username, password, role } = req.body;

  if (!username || !password || !role) {
    console.log('❌ Missing required fields');
    return res.status(400).json({ error: 'እባክዎ ሙሉ መረጃ ያስገቡ! (ስም, የይለፍ ቃል, ሚና)' });
  }

  // ሱፐር አድሚን ሌላ ሱፐር አድሚን መፍጠር አይችልም
  if (role === 'superadmin') {
    return res.status(400).json({ error: 'ተጨማሪ Super Admin መፍጠር አይቻልም!' });
  }

  // ስሙ አስቀድሞ መያዙን ማረጋገጥ
  const existingUser = users.find(u => u.username === username);
  if (existingUser) {
    return res.status(400).json({ error: `ይህ የተጠቃሚ ስም '${username}' አስቀድሞ ተይዟል!` });
  }

  // ፓስዎርድ ቢያንስ 6 ቁምፊ መሆኑን ማረጋገጥ
  if (password.length < 6) {
    return res.status(400).json({ error: 'የይለፍ ቃል ቢያንስ 6 ቁምፊዎች መሆን አለበት!' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      username,
      passwordHash: hashedPassword,
      role
    };
    users.push(newUser);
    
    console.log('✅ User created successfully:', { username, role });
    console.log('📊 Total users:', users.length);
    
    res.json({ 
      message: `አዲስ ${role === 'admin' ? 'አድሚን' : 'ተጠቃሚ'} '${username}' በተሳካ ሁኔታ ተፈጥሯል!`,
      user: { username, role }
    });
  } catch (error) {
    console.error('❌ Error creating user:', error);
    res.status(500).json({ error: 'ተጠቃሚ መፍጠር አልተቻለም! እባክዎ በኋላ ይሞክሩ.' });
  }
});

// ============================================================
// 5. ተጠቃሚ የማጥፊያ API (Super Admin ብቻ)
// ============================================================
app.delete('/api/users/:username', authenticateToken, (req, res) => {
  // ሱፐር አድሚን ብቻ ተጠቃሚ መሰረዝ ይችላል
  if (req.user.role !== 'superadmin') {
    return res.status(403).json({ error: 'ይህንን ድርጊት መፈጸም የሚችለው Super Admin ብቻ ነው!' });
  }

  const { username } = req.params;
  
  // ሱፐር አድሚን እራሱን መሰረዝ አይችልም
  if (username === 'superadmin') {
    return res.status(400).json({ error: 'Super Admin አካውንትን ማጥፋት አይቻልም!' });
  }

  // ተጠቃሚው መኖሩን ማረጋገጥ
  const userExists = users.find(u => u.username === username);
  if (!userExists) {
    return res.status(404).json({ error: 'ተጠቃሚው አልተገኘም!' });
  }

  users = users.filter(u => u.username !== username);
  res.json({ message: `ተጠቃሚ '${username}' ተሰርዟል!` });
});

// ============================================================
// 6. የሱፐር አድሚን ይለፍ ቃል መቀየሪያ API
// ============================================================
app.post('/api/superadmin/change-password', authenticateToken, async (req, res) => {
  if (req.user.role !== 'superadmin') {
    return res.status(403).json({ error: 'ይህንን ድርጊት መፈጸም የሚችለው Super Admin ብቻ ነው!' });
  }

  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'እባክዎ ሁለቱንም የይለፍ ቃላት ያስገቡ!' });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'አዲሱ የይለፍ ቃል ቢያንስ 6 ቁምፊዎች መሆን አለበት!' });
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
  res.json({ message: 'የሱፐር አድሚን የይለፍ ቃል በተሳካ ሁኔታ ተቀይሯል!' });
});

// ============================================================
// 7. Report APIs
// ============================================================

// ሁሉንም ሪፖርቶች ማውጣት
app.get('/api/report', authenticateToken, (req, res) => {
  res.json(reports);
});

// አዲስ ሪፖርት መፍጠር (ተጠቃሚ ብቻ)
app.post('/api/report', authenticateToken, (req, res) => {
  if (req.user.role === 'superadmin' || req.user.role === 'admin') {
    return res.status(403).json({ error: 'ሪፖርት መሙላት የሚችለው ተጠቃሚ (User) ብቻ ነው!' });
  }

  const newReport = { 
    id: Date.now(), 
    ...req.body, 
    enteredBy: req.user.username 
  };
  reports.push(newReport);
  res.json({ message: 'መረጃው በተሳካ ሁኔታ ተመዝግቧል!' });
});

// ሪፖርት መሰረዝ (ሱፐር አድሚን ብቻ)
app.delete('/api/report/:id', authenticateToken, (req, res) => {
  if (req.user.role !== 'superadmin') {
    return res.status(403).json({ error: 'ሪፖርት ማጥፋት የሚችለው Super Admin ብቻ ነው!' });
  }

  const reportId = parseInt(req.params.id);
  const reportExists = reports.find(r => r.id === reportId);
  
  if (!reportExists) {
    return res.status(404).json({ error: 'ሪፖርቱ አልተገኘም!' });
  }

  reports = reports.filter(r => r.id !== reportId);
  res.json({ message: 'ሪፖርቱ በተሳካ ሁኔታ ተሰርዟል!' });
});

// ============================================================
// 8. ለማጣራት - ሁሉንም ተጠቃሚዎች ማየት (Debug)
// ============================================================
app.get('/api/debug/users', authenticateToken, (req, res) => {
  if (req.user.role !== 'superadmin') {
    return res.status(403).json({ error: 'ይህንን መረጃ ማየት የሚችለው Super Admin ብቻ ነው!' });
  }
  const safeUsers = users.map(u => ({ 
    username: u.username, 
    role: u.role,
    hasPassword: !!u.passwordHash
  }));
  res.json({ 
    totalUsers: users.length,
    users: safeUsers 
  });
});

// ============================================================
// 9. ስርዓቱን ማስጀመር
// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('='.repeat(50));
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`✅ Default Super Admin:`);
  console.log(`   Username: superadmin`);
  console.log(`   Password: admin123`);
  console.log('='.repeat(50));
  console.log('📝 Use this to login and create other accounts');
  console.log('='.repeat(50));
});
