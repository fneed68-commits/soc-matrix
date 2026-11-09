require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const axios = require('axios');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());

// ==========================================
// إعدادات Supabase والمنصة
// ==========================================
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const PLATFORM_API_URL = "https://arabic-business-experts.vercel.app/api/chat";
const SECURITY_AGENT_SLUG = "security-expert";

let ipTracker = {};
let blockedIPs = new Set(); 
let alertCounter = 0;

// ==========================================
// محرك التحليل
// ==========================================
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
    } 
    else if (failedLogins >= 3 || scannedPorts >= 5) {
        createAlert(ip, "Suspicious Activity (Needs Review)", "Medium", 50, false);
        ipTracker[ip] = [];
    }
}

async function createAlert(ip, threatType, severity, score, autoContain) {
    alertCounter++;
    const uniqueId = `INC-${Date.now().toString().slice(-5)}-${alertCounter}`;
    
    let status = "Under Review";
    if (autoContain) {
        status = "Ephemeral-Contained";
        blockedIPs.add(ip);
    }

    const alert = {
        id: uniqueId, severity, threattype: threatType, sourceip: ip,
        trustscore: score, status: status,
        time: new Date().toLocaleTimeString('en-US', { hour12: false })
    };
    
    // حفظ في Supabase
    const { error } = await supabase.from('alerts').insert([alert]);
    if (!error) {
        io.emit('new_alert', {
            id: alert.id, severity: alert.severity, threatType: alert.threattype,
            sourceIp: alert.sourceip, trustScore: alert.trustscore,
            status: alert.status, time: alert.time
        });
    } else {
        console.error("Supabase Error:", error);
    }
}

// ==========================================
// WebSockets & APIs
// ==========================================
io.on('connection', async (socket) => {
    console.log('🟢 واجهة متصلة');
    const { data, error } = await supabase.from('alerts').select('*').order('time', { ascending: false }).limit(20);
    if (!error && data) {
        data.forEach(alert => socket.emit('new_alert', {
            id: alert.id, severity: alert.severity, threatType: alert.threattype,
            sourceIp: alert.sourceip, trustScore: alert.trustscore,
            status: alert.status, time: alert.time
        }));
    }
});

app.get('/api/stats', async (req, res) => {
    const { count: total } = await supabase.from('alerts').select('*', { count: 'exact', head: true });
    const { count: critical } = await supabase.from('alerts').select('*', { count: 'exact', head: true }).eq('severity', 'Critical');
    res.json({ total_blocked: total || 0, critical_active: critical || 0 });
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

app.post('/api/mitigate', async (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: "IP required" });
    
    blockedIPs.add(ip);
    await supabase.from('alerts').update({ status: 'Permanently-Blocked' }).eq('sourceip', ip);
    io.emit('ip_mitigated', ip);
    res.json({ success: true });
});

// محاكي الهجمات
setInterval(() => {
    const ips = ['185.22.1.10', '45.11.2.55', '103.4.5.6', '192.168.1.5'];
    const ip = ips[Math.floor(Math.random() * ips.length)];
    const event = Math.random() > 0.5 ? 'LOGIN_FAILED' : 'PORT_SCAN';
    const telemetrySpike = Math.random() > 0.4; 
    
    for(let i=0; i<5; i++) analyzeLog({ ip, eventType: event, port: Math.floor(Math.random() * 1000), telemetrySpike });
}, 8000);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`🚀 SOC Matrix connected to Supabase & running on port ${PORT}`));
