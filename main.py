from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Dict
from datetime import datetime, timedelta
from collections import defaultdict
import uuid

# ==========================================
# 1. تهيئة التطبيق والوسائط (Middleware)
# ==========================================
app = FastAPI(
    title="SOC Matrix Enterprise API",
    description="Security Operations Center Backend Engine",
    version="3.0.0"
)

# السماح للواجهة الأمامية (HTML) بالاتصال بالسيرفر
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# 2. نماذج البيانات (Pydantic Models)
# ==========================================
class LogEntry(BaseModel):
    source_ip: str = Field(..., example="192.168.1.50")
    event_type: str = Field(..., example="LOGIN_FAILED") # LOGIN_FAILED, PORT_SCAN, MALWARE
    target_port: int = Field(default=0)
    message: str = Field(default="")

class Alert(BaseModel):
    id: str
    severity: str
    threat_type: str
    source_ip: str
    trust_score: int
    status: str
    timestamp: str

# ==========================================
# 3. قاعدة البيانات المؤقتة (In-Memory DB)
# ==========================================
ALERTS_DB: List[Alert] = []
# لتتبع سلوك الـ IP (لكشف Brute Force)
IP_TRACKER = defaultdict(list)

# ==========================================
# 4. محرك التحليل (The Detection Engine)
# ==========================================
def analyze_log(log: LogEntry):
    now = datetime.now()
    ip = log.source_ip
    
    # 1. تتبع السجل
    IP_TRACKER[ip].append({"time": now, "event": log.event_type, "port": log.target_port})
    
    # تنظيف السجلات القديمة (أقدم من دقيقة)
    IP_TRACKER[ip] = [x for x in IP_TRACKER[ip] if now - x["time"] < timedelta(minutes=1)]
    
    recent_events = IP_TRACKER[ip]
    failed_logins = sum(1 for x in recent_events if x["event"] == "LOGIN_FAILED")
    ports_accessed = set(x["port"] for x in recent_events if x["event"] == "PORT_SCAN")

    # منطق اكتشاف Brute Force (أكثر من 3 محاولات فاشلة في دقيقة)
    if failed_logins >= 3:
        create_alert(ip, "Brute Force Attack", "Critical", 10)
        IP_TRACKER[ip].clear() # تصفير بعد اكتشاف الهجوم
    
    # منطق اكتشاف Port Scan (أكثر من 5 منافذ مختلفة في دقيقة)
    elif len(ports_accessed) >= 5:
        create_alert(ip, "Port Scanning", "High", 25)
        IP_TRACKER[ip].clear()

def create_alert(ip: str, threat_type: str, severity: str, trust_score: int):
    new_alert = Alert(
        id=f"INC-{str(uuid.uuid4())[:4].upper()}",
        severity=severity,
        threat_type=threat_type,
        source_ip=ip,
        trust_score=trust_score,
        status="Auto-Contained",
        timestamp=datetime.now().strftime("%H:%M:%S")
    )
    ALERTS_DB.insert(0, new_alert)
    if len(ALERTS_DB) > 50: ALERTS_DB.pop() # الاحتفاظ بآخر 50 تنبيه فقط

# ==========================================
# 5. نقاط النهاية (API Endpoints)
# ==========================================

@app.post("/api/logs", status_code=status.HTTP_202_ACCEPTED)
async def receive_log(log: LogEntry):
    """نقطة النهاية لاستقبال السجلات من الوكلاء (Agents)"""
    analyze_log(log)
    return {"message": "Log processed successfully"}

@app.get("/api/alerts", response_model=List[Alert])
async def get_alerts():
    """إرجاع التنبيهات للواجهة الأمامية"""
    return ALERTS_DB

@app.get("/api/stats")
async def get_stats():
    """إحصائيات لوحة التحكم"""
    total_blocked = len(ALERTS_DB)
    critical = sum(1 for a in ALERTS_DB if a.severity == "Critical")
    return {
        "total_blocked": total_blocked,
        "critical_active": critical,
        "system_status": "Online"
    }

# ==========================================
# 6. محاكي الهجمات (للتجربة)
# ==========================================
import random
import asyncio

@app.on_event("startup")
async def start_simulation():
    """يقوم بتوليد هجمات وهمية كل 5 ثوانٍ لتجربة النظام"""
    async def sim_loop():
        while True:
            await asyncio.sleep(5)
            ips = ["185.22.1.10", "45.11.2.55", "103.4.5.6"]
            ip = random.choice(ips)
            # توليد هجمات عشوائية
            event = random.choice(["LOGIN_FAILED", "PORT_SCAN", "MALWARE"])
            log = LogEntry(source_ip=ip, event_type=event, target_port=random.randint(1, 1000))
            analyze_log(log)
    
    asyncio.create_task(sim_loop())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
