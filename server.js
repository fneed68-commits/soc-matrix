require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const PLATFORM_API_URL = "https://arabic-business-experts.vercel.app/api/chat";
const SECURITY_AGENT_SLUG = "security-expert";
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_soc_key_123';

let ipTracker = {};
let blockedIPs = new Set(); 
let alertCounter = 0;

// ==========================================
// المصادقة (Authentication)
// ==========================================
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const { data: user, error } = await supabase.from('users').select('*').eq('email', email).single();
    
    if (error || !user) return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });

    const token = jwt.sign({ id: user.id, role: user.role, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, role: user.role });
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

function authorizeAdmin(req, res, next) {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'غير مصرح لك بهذا الإجراء' });
    next();
}

// ==========================================
// محرك التحليل و WebSockets
// ==========================================
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error("Authentication error"));
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return next(new Error("Authentication error"));
        socket.user = decoded;
        next();
    });
});

function analyzeLog(log) {
    const { ip, eventType, port, telemetrySpike } = log;
    if (blockedIPs.has(ip)) return;
    const now = Date.now();
    if (!ipTracker[ip]) ipTracker[ip] = [];
    ipTracker[ip].push({ time: now, event: eventType, port });
    ipTracker[ip] = ipTracker[ip].filter(l => now - l.time < 60000);

    const recentLogs = ipTracker[ip];
    const failedLogins = recentLogs.filter(l => l.event === 'LOGIN_FAILED').length;
    const scannedPorts = new Set(recentLogs.filter(l => l.event === 'PORT_SCAN').map(l => l.port)).size;

    if (telemetrySpike && (failedLogins >= 3 || scannedPorts >= 5)) {
        createAlert(ip, failedLogins >= 3 ? "Brute Force (Telemetry Verified)" : "Port Scan (Telemetry Verified)", "Critical", 10, true);
        ipTracker[ip] = []; 
    } else if (failedLogins >= 3 || scannedPorts >= 5) {
        createAlert(ip, "Suspicious Activity (Needs Review)", "Medium", 50, false);
        ipTracker[ip] = [];
    }
}

async function createAlert(ip, threatType, severity, score, autoContain) {
    alertCounter++;
    const uniqueId = `INC-${Date.now().toString().slice(-5)}-${alertCounter}`;
    let status = autoContain ? "Ephemeral-Contained" : "Under Review";
    if (autoContain) blockedIPs.add(ip);

    const alert = { id: uniqueId, severity, threattype: threatType, sourceip: ip, trustscore: score, status, time: new Date().toLocaleTimeString('en-US', { hour12: false }) };
    
    const { error } = await supabase.from('alerts').insert([alert]);
    if (!error) io.emit('new_alert', { id: alert.id, severity: alert.severity, threatType: alert.threattype, sourceIp: alert.sourceip, trustScore: alert.trustscore, status: alert.status, time: alert.time });
}

io.on('connection', async (socket) => {
    const { data, error } = await supabase.from('alerts').select('*').order('time', { ascending: false }).limit(20);
    if (!error && data) {
        data.forEach(alert => socket.emit('new_alert', { id: alert.id, severity: alert.severity, threatType: alert.threattype, sourceIp: alert.sourceip, trustScore: alert.trustscore, status: alert.status, time: alert.time }));
    }
});

// ==========================================
// APIs
// ==========================================
app.get('/api/stats', authenticateToken, async (req, res) => {
    const { count: total } = await supabase.from('alerts').select('*', { count: 'exact', head: true });
    const { count: critical } = await supabase.from('alerts').select('*', { count: 'exact', head: true }).eq('severity', 'Critical');
    res.json({ total_blocked: total || 0, critical_active: critical || 0 });
});

app.post('/api/logs', async (req, res) => {
    const { ip, eventType, port } = req.body;
    if (!ip || !eventType) return res.status(400).json({ error: "Missing data" });
    console.log(`📥 سجل حقيقي: ${eventType} من ${ip}`);
    analyzeLog({ ip, eventType, port: port || 0, telemetrySpike: true });
    res.status(202).json({ message: "Log processed" });
});

app.post('/api/analyze', authenticateToken, async (req, res) => {
    const { threatType, sourceIp, severity } = req.body;
    const prompt = `أنت خبير SOC. هجوم: ${threatType} من ${sourceIp} (خطورة: ${severity}). اكتب خطة استجابة من 3 خطوات مختصرة باللغة العربية.`;
    try {
        const response = await axios.post(PLATFORM_API_URL, { messages: [{ role: "user", content: prompt }], agentSlug: SECURITY_AGENT_SLUG }, { headers: { 'Content-Type': 'application/json' }, timeout: 30000 });
        res.json({ analysis: response.data.reply || "لم يتم استلام رد." });
    } catch (error) {
        res.status(500).json({ error: `فشل الاتصال: ${error.message}` });
    }
});

app.post('/api/mitigate', authenticateToken, authorizeAdmin, async (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: "IP required" });
    blockedIPs.add(ip);
    await supabase.from('alerts').update({ status: 'Permanently-Blocked' }).eq('sourceip', ip);
    io.emit('ip_mitigated', ip);
    res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`🚀 SOC Matrix (Secured) running on port ${PORT}`));
