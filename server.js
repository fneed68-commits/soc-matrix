require('dotenv').config();
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

const db = new sqlite3.Database('./soc_database.db');
db.run(`CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, severity TEXT, threatType TEXT, sourceIp TEXT, trustScore INTEGER, status TEXT, time TEXT)`);

let ipTracker = {};
let blockedIPs = new Set(); 
let ephemeralTimers = {}; // لتتبع الحظر المؤقت
let alertCounter = 0;

// ==========================================
// محرك التحليل (Dual-Signal Gating)
// ==========================================
function analyzeLog(log) {
    const { ip, eventType, port, telemetrySpike } = log;
    
    // إذا كان الـ IP محظوراً، تجاهل الهجمات
    if (blockedIPs.has(ip)) return;

    const now = Date.now();
    if (!ipTracker[ip]) ipTracker[ip] = [];
    ipTracker[ip].push({ time: now, event: eventType, port });
    ipTracker[ip] = ipTracker[ip].filter(l => now - l.time < 60000);

    const recentLogs = ipTracker[ip];
    const failedLogins = recentLogs.filter(l => l.event === 'LOGIN_FAILED').length;
    const scannedPorts = new Set(recentLogs.filter(l => l.event === 'PORT_SCAN').map(l => l.port)).size;

    // الإشارة التقنية الحتمية (Telemetry Signal)
    // في الواقع، هذه تأتي من مراقبة الشبكة (مثل RPS Spike)
    if (telemetrySpike && (failedLogins >= 3 || scannedPorts >= 5)) {
        // احتواء مؤقت (15 ثانية في العرض التجريبي)
        createAlert(ip, failedLogins >= 3 ? "Brute Force (Telemetry Verified)" : "Port Scan (Telemetry Verified)", "Critical", 10, true);
        ipTracker[ip] = []; 
    } 
    // إذا لم تكن هناك إشارة تقنية، نسجل الحادث كـ "تحت المراجعة" (لا نحظر تلقائياً)
    else if (failedLogins >= 3 || scannedPorts >= 5) {
        createAlert(ip, "Suspicious Activity (Needs Review)", "Medium", 50, false);
        ipTracker[ip] = [];
    }
}

function createAlert(ip, threatType, severity, score, autoContain) {
    alertCounter++;
    const uniqueId = `INC-${Date.now().toString().slice(-5)}-${alertCounter}`;
    
    // إذا كان احتواءً تلقائياً، نضيفه لقائمة الحظر المؤقت
    let status = "Under Review";
    if (autoContain) {
        status = "Ephemeral-Contained";
        blockedIPs.add(ip);
        
        // فك الحظر التلقائي بعد 15 ثانية (Auto-TTL)
        if (ephemeralTimers[ip]) clearTimeout(ephemeralTimers[ip]);
        ephemeralTimers[ip] = setTimeout(() => {
            blockedIPs.delete(ip);
            console.log(`⏱️ انتهى الحظر المؤقت للـ IP: ${ip}`);
            io.emit('ip_unblocked', ip); // إبلاغ الواجهة
        }, 15000); 
    }

    const alert = {
        id: uniqueId, severity, threatType, sourceIp: ip,
        trustScore: score, status: status,
        time: new Date().toLocaleTimeString('en-US', { hour12: false })
    };
    
    const stmt = db.prepare(`INSERT OR IGNORE INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?)`);
    stmt.run(alert.id, alert.severity, alert.threatType, alert.sourceIp, alert.trustScore, alert.status, alert.time, (err) => {
        if (!err) io.emit('new_alert', alert);
    });
    stmt.finalize();
}

// ==========================================
// WebSockets & APIs
// ==========================================
io.on('connection', (socket) => {
    db.all(`SELECT * FROM alerts ORDER BY rowid DESC LIMIT 20`, [], (err, rows) => {
        if (!err && rows) rows.forEach(alert => socket.emit('new_alert', alert));
    });
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
        const response = await axios.post(PLATFORM_API_URL, {
            messages: [{ role: "user", content: prompt }], agentSlug: SECURITY_AGENT_SLUG
        }, { headers: { 'Content-Type': 'application/json' }, timeout: 30000 });
        res.json({ analysis: response.data.reply || "لم يتم استلام رد." });
    } catch (error) {
        res.status(500).json({ error: `فشل الاتصال بالمنصة: ${error.message}` });
    }
});

// تثبيت الحظر يدوياً (Human-in-the-loop)
app.post('/api/mitigate', (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: "IP required" });
    
    // إلغاء المؤقت المؤقت (Auto-TTL) وجعله حظراً دائماً
    if (ephemeralTimers[ip]) clearTimeout(ephemeralTimers[ip]);
    blockedIPs.add(ip);
    
    db.run(`UPDATE alerts SET status = 'Permanently-Blocked' WHERE sourceIp = ?`, [ip]);
    io.emit('ip_mitigated', ip);
    res.json({ success: true });
});

// ==========================================
// محاكي الهجمات
// ==========================================
setInterval(() => {
    const ips = ['185.22.1.10', '45.11.2.55', '103.4.5.6', '192.168.1.5'];
    const ip = ips[Math.floor(Math.random() * ips.length)];
    const event = Math.random() > 0.5 ? 'LOGIN_FAILED' : 'PORT_SCAN';
    // محاكاة الإشارة التقنية (Telemetry Spike) بنسبة 60%
    const telemetrySpike = Math.random() > 0.4; 
    
    for(let i=0; i<5; i++) analyzeLog({ ip, eventType: event, port: Math.floor(Math.random() * 1000), telemetrySpike });
}, 8000);

server.listen(3000, () => console.log(`🚀 SOC Matrix (Dual-Signal) running on port 3000`));
