# 🛡️ SOC Matrix - AI-Powered Security Operations Center

An advanced, fully functional Security Operations Center (SOC) built entirely from an Android device using **Termux**. 

This project demonstrates the power of local-first AI and lightweight, full-stack web development.

## 🚀 Features
- **Real-time Threat Detection:** Monitors logs for Brute Force and Port Scanning attacks.
- **Live Dashboard:** Real-time data streaming using WebSockets (Socket.io).
- **AI Incident Response:** Integrated with the **"Arabic Business Experts"** platform (36 AI Agents). The "Security Engineer" agent generates custom 3-step mitigation playbooks instantly.
- **Autonomous Mitigation (Simulation):** One-click IP blocking simulation to update incident status.
- **Persistent Storage:** Uses SQLite to ensure no logs are lost.

## 🛠️ Tech Stack
- **Backend:** Node.js, Express.js, Socket.io
- **Database:** SQLite3
- **Frontend:** Vanilla HTML, CSS (Glassmorphism & Dark Mode), JavaScript
- **AI Engine:** REST API integration with Groq API via "Arabic Business Experts" platform.

## ⚙️ How to Run Locally
1. Install dependencies:
   ```bash
   npm install
