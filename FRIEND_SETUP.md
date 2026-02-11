# 🚀 XXE XLSX Tool - Setup for Friends

## 📦 Quick Setup (Any Country)

### Prerequisites
- Docker Desktop installed
- Git (optional)

### Method 1: GitHub Clone
```bash
git clone https://github.com/Bhuvanesh3602/XXE-XLSX-INJECTION-TOOL-.git
cd XXE-XLSX-INJECTION-TOOL-
docker-compose up -d
```

### Method 2: Download ZIP
1. Download project ZIP file
2. Extract to folder
3. Open terminal in folder
4. Run: `docker-compose up -d`

### Method 3: Manual Setup (No Docker)
```bash
# Backend
cd backend
pip install -r requirements.txt
python app.py

# Frontend (new terminal)
cd frontend
npm install
npm start
```

## 🌐 Access Points
- Frontend: http://localhost:3000
- Backend API: http://localhost:5000
- Health Check: http://localhost:5000/api/health

## 🔧 Commands
```bash
# Start
docker-compose up -d

# Stop
docker-compose down

# View logs
docker-compose logs -f

# Rebuild
docker-compose up -d --build
```

## 📱 Share This File
Send this file along with the project code!