// โหลดค่า .env
require('dotenv').config({ path: __dirname + '/.env' });

console.log("✅ DEBUG: JWT_SECRET =", process.env.JWT_SECRET);

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const path = require('path');
const fs = require('fs');
const multer = require('multer');

const jwt = require("jsonwebtoken");

const app = express();

// ----------------- ✅ การตั้งค่า CORS -----------------
const allowedOrigins = [
    'http://localhost:3001',
    'http://localhost:3000',
    'http://localhost:5173',
    // ✅ เพิ่ม URL ของ Netlify จริง (ไม่มี / ต่อท้าย)
    'https://repair-syste.netlify.app'
];

app.use(cors({
    origin: (origin, callback) => {
        if (!origin) return callback(null, true); 
        if (allowedOrigins.includes(origin) || origin.endsWith('.netlify.app')) {
            callback(null, true);
        } else {
            console.log(`❌ CORS Blocked: Origin ${origin} not allowed`);
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
    credentials: true,
}));


app.use(express.json());

// serve uploaded files
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
app.use('/uploads', express.static(uploadDir));

// multer storage
const storage = multer.diskStorage({
  destination: function (req, file, cb) { cb(null, uploadDir); },
  filename: function (req, file, cb) {
    const unique = Date.now() + '-' + Math.round(Math.random()*1e9);
    const safe = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
    cb(null, `${unique}-${safe}`);
  }
});
const upload = multer({ storage });

// ----------------- ✅ การเชื่อมต่อ MongoDB -----------------
const mongoUri = process.env.MONGO_URI; // ใช้ค่าใหม่จาก .env เท่านั้น

mongoose.connect(mongoUri)
  .then(() => console.log("✅ Connected to MongoDB Atlas"))
  .catch(err => console.error("❌ MongoDB connection error:", err));

// ✅ Schema: แจ้งซ่อม
const requestSchema = new mongoose.Schema({
  device: String,
  problem: String,
  reporter: String,
  images: [String],
  status: { type: String, default: "รอดำเนินการ" },
  date: String,
  updatedAt: String
});
const Request = mongoose.model("Request", requestSchema);

// ✅ Schema: แจ้งเหตุการณ์
const incidentSchema = new mongoose.Schema({
  reporter: String,
  detail: String,
  category: String,
  date: String
});
const Incident = mongoose.model("Incident", incidentSchema);

// ✅ ผู้ใช้แอดมิน (เดโม)
const adminUser = {
  username: 'admin',
  passwordHash: bcrypt.hashSync('1234', 10),
  role: 'admin'
};

// ✅ สร้าง JWT
function signToken(payload) {
  const secret = process.env.JWT_SECRET || 'dev-secret';
  return jwt.sign(payload, secret, { expiresIn: '2h' });
}

// ✅ ตรวจ JWT
function authRequired(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'ต้องการการยืนยันตัวตน' });
  }
  const token = auth.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'dev-secret');
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'โทเคนไม่ถูกต้องหรือหมดอายุ' });
  }
}

// ✅ ตรวจสิทธิ์แอดมิน
function adminOnly(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'ไม่อนุญาต' });
  }
  next();
}

// ------------------ Routes ------------------

// ✅ Route หลัก
app.get('/', (req, res) => {
  res.send('✅ Repair System Backend is running!');
});

// ✅ ล็อกอินแอดมิน
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'กรอกข้อมูลให้ครบ' });
  if (username !== adminUser.username) return res.status(401).json({ error: 'ผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });

  const isValid = await bcrypt.compare(password, adminUser.passwordHash);
  if (!isValid) return res.status(401).json({ error: 'ผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });

  const token = signToken({ username: adminUser.username, role: adminUser.role });
  res.json({ token });
});

// ✅ API: แจ้งซ่อม
// Accept JSON or multipart/form-data (with up to 2 images)
app.post("/api/requests", upload.array('images', 2), async (req, res) => {
  try {
    const body = req.body || {};
    const images = [];
    if (req.files && req.files.length) {
      req.files.forEach(f => {
        // full public URL
        const host = req.get('host');
        const protocol = req.protocol;
        images.push(`${protocol}://${host}/uploads/${f.filename}`);
      });
    }

    const newRequest = new Request({
      device: body.device || body.device,
      problem: body.problem || body.problem,
      reporter: body.reporter || body.reporter,
      images: images.length ? images : (body.images || []),
      date: body.date || new Date().toISOString().slice(0, 10),
      updatedAt: new Date().toISOString()
    });
    const saved = await newRequest.save();
    res.status(201).json(saved);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "เกิดข้อผิดพลาดในการบันทึก" });
  }
});

// ✅ API: ดูรายการแจ้งซ่อม
app.get("/api/requests", async (req, res) => {
  try {
    const { reporter } = req.query;
    if (reporter) {
      const list = await Request.find({ reporter });
      return res.json(list);
    } else {
      const auth = req.headers.authorization;
      if (!auth || !auth.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'ต้องการการยืนยันตัวตน' });
      }
      const token = auth.split(' ')[1];
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'dev-secret');
        if (decoded.role !== 'admin') {
          return res.status(403).json({ error: 'ไม่อนุญาต' });
        }
        const all = await Request.find({});
        return res.json(all);
      } catch (e) {
        return res.status(401).json({ error: 'โทเคนไม่ถูกต้องหรือหมดอายุ' });
      }
    }
  } catch (err) {
    res.status(500).json({ error: "เกิดข้อผิดพลาดในการดึงข้อมูล" });
  }
});

// ✅ API: เปลี่ยนสถานะคำร้อง
app.patch("/api/requests/:id", authRequired, adminOnly, async (req, res) => {
  try {
    const updated = await Request.findByIdAndUpdate(
      req.params.id,
      { status: req.body.status, updatedAt: new Date().toISOString() },
      { new: true }
    );
    if (!updated) return res.status(404).send("ไม่พบคำร้อง");
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: "เกิดข้อผิดพลาดในการอัปเดต" });
  }
});

// ✅ API: ลบรายการแจ้งซ่อมที่เก่ากว่า 30 วัน
app.delete("/api/requests/older-than-30-days", authRequired, adminOnly, async (req, res) => {
  try {
    const today = new Date();
    const cutoff = new Date(today.setDate(today.getDate() - 30));
    const cutoffStr = cutoff.toISOString().split("T")[0];
    const result = await Request.deleteMany({ date: { $lt: cutoffStr } });
    res.json({ message: `ลบข้อมูลแจ้งซ่อมที่เก่ากว่า 30 วันแล้วจำนวน ${result.deletedCount} รายการ` });
  } catch (err) {
    res.status(500).json({ error: "เกิดข้อผิดพลาดในการลบข้อมูลเก่า" });
  }
});

// ✅ API: แจ้งเหตุการณ์
app.post("/api/incidents", async (req, res) => {
  try {
    const newIncident = new Incident({
      ...req.body,
      date: req.body.date || new Date().toISOString().slice(0, 10)
    });
    const saved = await newIncident.save();
    res.status(201).json(saved);
  } catch (err) {
    res.status(500).json({ error: "เกิดข้อผิดพลาดในการบันทึกเหตุการณ์" });
  }
});

// ----------------- ✅ เริ่มเซิร์ฟเวอร์ -----------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT}`);
});
