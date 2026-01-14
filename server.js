// server.js // โหลดค่า .env
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
const mongoUri = process.env.MONGO_URI;

mongoose.connect(mongoUri)
  .then(() => console.log("✅ Connected to MongoDB Atlas"))
  .catch(err => console.error("❌ MongoDB connection error:", err));

// ✅ Schema: แจ้งซ่อม
const requestSchema = new mongoose.Schema({
  device: String,
  problem: String,
  reporter: String,
  images: [String], // จะเก็บเป็นชื่อไฟล์ เช่น "12345-image.jpg"
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

app.get('/', (req, res) => {
  res.send('✅ Repair System Backend is running!');
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'กรอกข้อมูลให้ครบ' });
  if (username !== adminUser.username) return res.status(401).json({ error: 'ผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });

  const isValid = await bcrypt.compare(password, adminUser.passwordHash);
  if (!isValid) return res.status(401).json({ error: 'ผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });

  const token = signToken({ username: adminUser.username, role: adminUser.role });
  res.json({ token });
});

// ✅ API: แจ้งซ่อม (แก้ไขจุดเก็บรูป)
app.post("/api/requests", upload.array('images', 2), async (req, res) => {
  try {
    const body = req.body || {};
    let images = [];

    // 1) จัดการไฟล์จาก Multer - เก็บเฉพาะชื่อไฟล์ลง DB
    if (req.files && req.files.length) {
      req.files.forEach(f => {
        images.push(f.filename); 
      });
    }

    // 2) จัดการไฟล์ Base64 (ถ้ามี)
    const extra = body.images ? (Array.isArray(body.images) ? body.images : [body.images]) : [];
    for (const item of extra) {
      if (!item) continue;
      
      // ถ้าเป็น URL อยู่แล้ว (เช่นจากที่อื่น) ให้เก็บตามเดิม
      if (typeof item === 'string' && (item.startsWith('http'))) {
        images.push(item);
        continue;
      }

      // ถ้าเป็น Base64 ให้ decode และเซฟลง uploads/ แล้วเก็บแค่ชื่อไฟล์
      if (typeof item === 'string' && item.startsWith('data:')) {
        const matches = item.match(/^data:(image\/[^;]+);base64,(.+)$/);
        if (matches) {
          const mime = matches[1];
          const b64 = matches[2];
          const ext = mime.split('/')[1].replace(/\+/g, '');
          const filename = `base64-${Date.now()}-${Math.round(Math.random()*1e9)}.${ext}`;
          const filepath = path.join(uploadDir, filename);
          try {
            fs.writeFileSync(filepath, Buffer.from(b64, 'base64'));
            images.push(filename); 
          } catch (e) {
            console.error('Failed to write decoded image', e);
          }
        }
      }
    }

    const newRequest = new Request({
      device: body.device,
      problem: body.problem,
      reporter: body.reporter,
      images: images, // เก็บ Array ของชื่อไฟล์
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

app.get("/api/requests", async (req, res) => {
  try {
    const { reporter } = req.query;
    let list;
    if (reporter) {
      list = await Request.find({ reporter });
    } else {
      const auth = req.headers.authorization;
      if (!auth || !auth.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'ต้องการการยืนยันตัวตน' });
      }
      const token = auth.split(' ')[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'dev-secret');
      if (decoded.role !== 'admin') {
        return res.status(403).json({ error: 'ไม่อนุญาต' });
      }
      list = await Request.find({});
    }

    // ก่อนส่งไป Frontend: แปลงชื่อไฟล์ให้เป็น URL เต็ม (เฉพาะตอนตอบกลับ)
    const host = req.get('host');
    const protocol = req.protocol;
    const formattedList = list.map(item => {
      const doc = item.toObject();
      doc.images = doc.images.map(img => {
        if (img.startsWith('http')) return img;
        return `${protocol}://${host}/uploads/${img}`;
      });
      return doc;
    });

    res.json(formattedList);
  } catch (err) {
    res.status(500).json({ error: "เกิดข้อผิดพลาดในการดึงข้อมูล" });
  }
});

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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT}`);
});