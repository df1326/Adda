const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const mongoose = require('mongoose');

const app = express();

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));

const JWT_SECRET = process.env.JWT_SECRET || 'your_strong_jwt_secret_key_change_this';

// ============================================================
// MongoDB Connection
// ============================================================
const MONGO_URI = process.env.MONGO_URI || "mongodb+srv://addisutsigie16_db_user:0q7UA21Lq8s0bdXZ@cluster0.dzl7lt9.mongodb.net/adda-system?retryWrites=true&w=majority&appName=Cluster0";

mongoose.connect(MONGO_URI)
  .then(() => {
    console.log("✅ MongoDB connected successfully!");
    initDefaultUsers(); // በምስሉ ላይ ያሉትን ተጠቃሚዎች በራስ-ሰር መፍጠር
  })
  .catch(err => console.error("❌ MongoDB connection error:", err));

// ============================================================
// Database Schemas
// ============================================================
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  role: { type: String, required: true, enum: ['superadmin', 'admin', 'user'] }
}, { timestamps: true });

const reportSchema = new mongoose.Schema({
  enteredBy: { type: String, required: true }, // የመዘገበው ተጠቃሚ username
  data: { type: mongoose.Schema.Types.Mixed }
}, { timestamps: true, strict: false });

const User = mongoose.model('User', userSchema);
const Report = mongoose.model('Report', reportSchema);

// ============================================================
// በምስሉ ላይ ያሉትን ተጠቃሚዎች በራስ-ሰር (Auto Seed) ማድረግ
// ============================================================
const defaultLocations = [
  "ባህር ዳር ከተማ", "ጎንደር ከተማ", "ደብረ ታቦር ከተማ", "ወልድያ ከተማ", "ደሴ ከተማ",
  "ኮምቦልቻ ከተማ", "ደብረ ብርሃን ከተማ", "ደብረ ማርቆስ ከተማ", "ማዕከላዊ ጎንደር ዞን",
  "ምዕራብ ጎንደር ዞን", "ሰሜን ጎንደር ዞን", "ወልቃይት ጠገዴ ሰቲት ሁመራ ዞን",
  "ደቡብ ጎንደር ዞን", "ሰሜን ወሎ ዞን", "ደቡብ ወሎ ዞን", "ሰሜን ሸዋ ዞን",
  "ምስራቅ ጎጃም ዞን", "ምዕራብ ጎጃም ዞን", "ሰሜን ጎጃም", "አዊ ብ/ሰ ዞን",
  "ዋግኸምራ ብ/ሰ ዞን", "ኦሮሞ ብ/ሰ ዞን"
];

async function initDefaultUsers() {
  try {
    // 1. Super Admin መኖሩን ማረጋገጥ
    const superAdminExists = await User.findOne({ username: 'superadmin' });
    if (!superAdminExists) {
      const defaultPassword = await bcrypt.hash('admin123', 10);
      await User.create({ username: 'superadmin', passwordHash: defaultPassword, role: 'superadmin' });
      console.log('✅ Superadmin initialized');
    }

    // 2. ዞኖችን እና ከተሞችን በራስ-ሰር መፍጠር (የመጀመሪያ ጊዜ የይለፍ ቃል: 123456)
    const defaultPasswordHash = await bcrypt.hash('123456', 10);
    for (const loc of defaultLocations) {
      const exists = await User.findOne({ username: loc });
      if (!exists) {
        await User.create({ username: loc, passwordHash: defaultPasswordHash, role: 'user' });
      }
    }
    console.log('✅ Default Zones and Cities users loaded into Database');
  } catch (error) {
    console.error('❌ Auto-seed error:', error);
  }
}

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
// 1. Login API
// ============================================================
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    
    if (!user) return res.status(401).json({ error: 'የተጠቃሚ ስም አልተገኘም!' });

    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) return res.status(401).json({ error: 'የተሳሳተ የይለፍ ቃል!' });

    const token = jwt.sign(
      { username: user.username, role: user.role }, 
      JWT_SECRET, 
      { expiresIn: '12h' }
    );
    res.json({ token, role: user.role, username: user.username });
  } catch (error) {
    res.status(500).json({ error: 'ስህተት ተከሰተ!' });
  }
});

// ============================================================
// 2. ተጠቃሚዎችን ማውጣት (ለ Super Admin እና Admin)
// ============================================================
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    if (req.user.role === 'user') {
      return res.status(403).json({ error: 'ፈቃድ የለዎትም!' });
    }
    const users = await User.find().select('username role createdAt -_id');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'ተጠቃሚዎችን ማውጣት አልተቻለም!' });
  }
});

// ============================================================
// 3. አዲስ ተጠቃሚ/አድሚን መፍጠር (Super Admin ብቻ)
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

    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).json({ error: 'ይህ ስም አስቀድሞ ተይዟል!' });

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ username, passwordHash: hashedPassword, role });
    
    res.json({ message: `አዲስ አካውንት '${username}' ተፈጥሯል!` });
  } catch (error) {
    res.status(500).json({ error: 'ተጠቃሚ መፍጠር አልተቻለም!' });
  }
});

// ============================================================
// 4. ተጠቃሚ መሰረዝ (Super Admin ብቻ)
// ============================================================
app.delete('/api/users/:username', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'superadmin') {
      return res.status(403).json({ error: 'Super Admin ብቻ ተጠቃሚ መሰረዝ ይችላል!' });
    }

    const { username } = req.params;
    if (username === 'superadmin') return res.status(400).json({ error: 'Super Admin መሰረዝ አይቻልም!' });

    await User.deleteOne({ username });
    res.json({ message: `ተጠቃሚ '${username}' ተሰርዟል!` });
  } catch (error) {
    res.status(500).json({ error: 'ተጠቃሚ መሰረዝ አልተቻለም!' });
  }
});

// ============================================================
// 5. ሪፖርት/መረጃዎችን ማውጣት (Strict Access Control)
// ============================================================
app.get('/api/report', authenticateToken, async (req, res) => {
  try {
    // ሱፐር አድሚን እና አድሚን የሁሉንም ያያሉ፤ ተጠቃሚ (User) ግን የራሱን ብቻ ያያል
    let query = {};
    if (req.user.role === 'user') {
      query.enteredBy = req.user.username;
    }

    const reports = await Report.find(query);
    res.json(reports);
  } catch (error) {
    res.status(500).json({ error: 'መረጃ ማውጣት አልተቻለም!' });
  }
});

// ============================================================
// 6. አዲስ መረጃ ማስገባት
// ============================================================
app.post('/api/report', authenticateToken, async (req, res) => {
  try {
    const newReport = new Report({
      enteredBy: req.user.username,
      data: req.body
    });
    
    await newReport.save();
    res.json({ message: 'መረጃው በስኬት ተመዝግቧል!' });
  } catch (error) {
    res.status(500).json({ error: 'መረጃ ማስገባት አልተቻለም!' });
  }
});

// ============================================================
// 7. የተመዘገበ መረጃን ኤዲት ማድረግ (Edit Own Data)
// ============================================================
app.put('/api/report/:id', authenticateToken, async (req, res) => {
  try {
    const report = await Report.findById(req.params.id);
    if (!report) return res.status(404).json({ error: 'መረጃው አልተገኘም!' });

    // ተጠቃሚ ከሆነ የራሱን መረጃ ብቻ ነው ኤዲት ማድረግ የሚችለው
    if (req.user.role === 'user' && report.enteredBy !== req.user.username) {
      return res.status(403).json({ error: 'የሌላ አካልን መረጃ ኤዲት ማድረግ አይችሉም!' });
    }

    report.data = req.body;
    await report.save();
    res.json({ message: 'መረጃው በስኬት ተስተካክሏል!' });
  } catch (error) {
    res.status(500).json({ error: 'ማስተካከል አልተቻለም!' });
  }
});

// ============================================================
// 8. ሪፖርት መሰረዝ
// ============================================================
app.delete('/api/report/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'superadmin') {
      return res.status(403).json({ error: 'Super Admin ብቻ መረጃ መሰረዝ ይችላል!' });
    }

    await Report.findByIdAndDelete(req.params.id);
    res.json({ message: 'መረጃው ተሰርዟል!' });
  } catch (error) {
    res.status(500).json({ error: 'መሰረዝ አልተቻለም!' });
  }
});

// ============================================================
// 9. የይለፍ ቃል መቀየር
// ============================================================
app.post('/api/change-password', authenticateToken, async (req, res) => {
  try {
    const { newPassword } = req.body;
    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({ error: 'የይለፍ ቃል ቢያንስ 6 ቁምፊ መሆን አለበት!' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await User.updateOne({ username: req.user.username }, { passwordHash: hashedPassword });

    res.json({ message: 'የይለፍ ቃል ተቀይሯል!' });
  } catch (error) {
    res.status(500).json({ error: 'የይለፍ ቃል መቀየር አልተቻለም!' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
