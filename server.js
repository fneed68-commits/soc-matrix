const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const axios = require('axios');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());

const PLATFORM_API_URL = "https://arabic-business-experts.vercel.app/api/chat";
const SECURITY_AGENT_SLUG = "security-expert";

// ==========================================
// 1. قاعدة البيانات وقائمة الحظر
// ==========================================
const db = new sqlite3.Database('./soc_database.db');
db.run(`CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY, severity TEXT, threatType TEXT, sourceIp TEXT, trustScore INTEGER, status TEXT, time TEXT
)`);

let ipTracker = {};
let blockedIPs = new Set(); 
let alertCounter = 0; // عدّاد لضمان عدم تكرار المعرفات

// ==========================================
// 2. محرك التحليل
// ==========================================
function analyzeLog(log) {
    const { ip, eventType, port } = log;
    if (blockedIPs.has(ip)) return;

    const now = Date.now();
    if (!ipTracker[ip]) ipTracker[ip] = [];
    ipTracker[ip].push({ time: now, event: eventType, port });
    ipTracker[ip] = ipTracker[ip].filter(l => now - l.time < 60000);

    const recentLogs = ipTracker[ip];
    const failedLogins = recentLogs.filter(l => l.event === 'LOGIN_FAILED').length;
    const scannedPorts = new Set(recentLogs.filter(l => l.event === 'PORT_SCAN').map(l => l.port)).size;

    if (failedLogins >= 3) { createAlert(ip, "Brute Force Attack", "Critical", 10); ipTracker[ip] = []; }
    else if (scannedPorts >= 5) { createAlert(ip, "Port Scanning", "High", 25); ipTracker[ip] = []; }
}

function createAlert(ip, threatType, severity, score) {
    alertCounter++;
    // معرف فريد 100% باستخدام الوقت + العدّاد
    const uniqueId = `INC-${Date.now().toString().slice(-5)}-${alertCounter}`;
    
    const alert = {
        id: uniqueId, severity, threatType, sourceIp: ip,
        trustScore: score, status: "Auto-Contained",
        time: new Date().toLocaleTimeString('en-US', { hour12: false })
    };
    
    // استخدام INSERT OR IGNORE لتجاهل التكرار بدلاً من الانهيار
    const stmt = db.prepare(`INSERT OR IGNORE INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?)`);
    
    // إضافة مستمع للخطأ لمنع انهيار السيرفر نهائياً
    stmt.on('error', (err) => {
        console.log(`⚠️ خطأ في قاعدة البيانات (تم تجاهله): ${err.message}`);
    });

    stmt.run(alert.id, alert.severity, alert.threatType, alert.sourceIp, alert.trustScore, alert.status, alert.time, (err) => {
        if (!err) {
            io.emit('new_alert', alert);
        }
    });
    stmt.finalize();
}

// ==========================================
// 3. WebSockets
// ==========================================
io.on('connection', (socket) => {
    console.log('🟢 واجهة متصلة');
    db.all(`SELECT * FROM alerts ORDER BY rowid DESC LIMIT 20`, [], (err, rows) => {
        if (!err && rows) rows.forEach(alert => socket.emit('new_alert', alert));
    });
});

// ==========================================
// 4. APIs
// ==========================================
app.get('/api/alerts', (req, res) => {
    db.all(`SELECT * FROM alerts ORDER BY rowid DESC LIMIT 50`, [], (err, rows) => res.json(rows || []));
});

app.get('/api/stats', (req, res) => {
    db.get(`SELECT COUNT(*) as total_blocked, SUM(CASE WHEN severity='Critical' THEN 1 ELSE 0 END) as critical_active FROM alerts`, [], (err, row) => {
        res.json({ total_blocked: row?.total_blocked || 0, critical_active: row?.critical_active || 0 });
    });
});

app.post('/api/analyze', async (req, res) => {
    const { threatType, sourceIp, severity } = req.body;
    const prompt = `أنت خبير SOC. هجوم: ${threatType} من ${sourceIp} (خطورة: ${severity}). اكتب خطة استجابة من 3 خطوات مختصرة باللغة العربية.`;
    
    try {
        console.log(`🧠 إرسال الطلب إلى منصة خبراء الأعمال للهجوم: ${threatType}`);
        const response = await axios.post(PLATFORM_API_URL, {
            messages: [{ role: "user", content: prompt }],
            agentSlug: SECURITY_AGENT_SLUG
        }, {
            headers: { 'Content-Type': 'application/json' },
            timeout: 30000
        });
        const analysis = response.data.reply || response.data.error || "لم يتم استلام رد.";
        res.json({ analysis });
    } catch (error) {
        console.error("❌ خطأ:", error.message);
        res.status(500).json({ error: `فشل الاتصال بالمنصة: ${error.message}` });
    }
});

app.post('/api/mitigate', (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: "IP required" });

    blockedIPs.add(ip);
    console.log(`🛡️ تم حظر الـ IP بنجاح (محاكاة): ${ip}`);

    db.run(`UPDATE alerts SET status = 'Mitigated' WHERE sourceIp = ?`, [ip]);
    io.emit('ip_mitigated', ip);

    res.json({ success: true, message: `تم حظر ${ip} وتحديث حالته.` });
});

// ==========================================
// 5. محاكي الهجمات
// ==========================================
setInterval(() => {
    const ips = ['185.22.1.10', '45.11.2.55', '103.4.5.6', '192.168.1.5'];
    const ip = ips[Math.floor(Math.random() * ips.length)];
    const event = Math.random() > 0.5 ? 'LOGIN_FAILED' : 'PORT_SCAN';
    for(let i=0; i<5; i++) analyzeLog({ ip, eventType: event, port: Math.floor(Math.random() * 1000) });
}, 8000);

server.listen(3000, () => console.log(`🚀 SOC Matrix running on port 3000`));
