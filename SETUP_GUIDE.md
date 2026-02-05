# 🚀 Installation & Setup Guide

## Prerequisites

- **Python 3.8+** - [Download](https://python.org/downloads/)
- **Node.js 16+** - [Download](https://nodejs.org/)
- **npm** (comes with Node.js)

## Quick Setup

### 1. Clone Repository
```bash
git clone https://github.com/bhuvanesh3602/XXE-XLSX-INJECTION-TOOL-.git
cd XXE-XLSX-INJECTION-TOOL-
```

### 2. Backend Setup
```bash
cd backend
pip install flask flask-cors openpyxl lxml
```

### 3. Frontend Setup
```bash
cd frontend
npm install react react-dom axios
npm start
```

### 4. Start Backend
```bash
cd backend
python app.py
```

## Access Application

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:5000

## Required Dependencies

### Backend (Python)
```txt
flask==2.3.3
flask-cors==4.0.0
openpyxl==3.1.2
lxml==4.9.3
```

### Frontend (Node.js)
```json
{
  "react": "^18.2.0",
  "react-dom": "^18.2.0",
  "axios": "^1.5.0"
}
```

## Usage Steps

1. Open http://localhost:3000
2. Upload XLSX file
3. Configure payload parameters
4. Select attack type (DOCTYPE/XInclude/DTD/SVG)
5. Generate and download weaponized file

## Troubleshooting

- **Port conflicts**: Change ports in app.py (backend) or package.json (frontend)
- **CORS errors**: Ensure flask-cors is installed
- **File upload issues**: Check file permissions in processed/ directory

⚠️ **For authorized security testing only**