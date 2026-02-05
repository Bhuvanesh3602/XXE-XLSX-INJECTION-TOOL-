# Network Deployment Guide

## For Others to Access Your Project

### Option 1: Quick Network Deployment
```cmd
cd d:\Project\xxe-xlsx-tool\xxe-xlsx-tool
.\deploy-network.bat
```

### Option 2: Manual Network Setup

1. **Find your IP address:**
```cmd
ipconfig
```
Look for IPv4 Address (e.g., 192.168.1.100)

2. **Start backend:**
```cmd
cd backend
python app.py
```

3. **Start frontend with your IP:**
```cmd
cd frontend
set REACT_APP_API_URL=http://YOUR_IP:5000
npm start
```

### Access URLs
- **Your computer**: http://localhost:3000
- **Others on network**: http://YOUR_IP:3000
- **API Health**: http://YOUR_IP:5000/api/health

### Firewall Setup
Allow ports 3000 and 5000 in Windows Firewall:
```cmd
netsh advfirewall firewall add rule name="XXE Tool Frontend" dir=in action=allow protocol=TCP localport=3000
netsh advfirewall firewall add rule name="XXE Tool Backend" dir=in action=allow protocol=TCP localport=5000
```

### Cloud Deployment Options

#### Vercel (Frontend)
```cmd
cd frontend
npm install -g vercel
vercel --prod
```

#### Railway/Heroku (Full Stack)
- Push to GitHub
- Connect to Railway/Heroku
- Deploy automatically

#### AWS/Azure (Production)
- Use Docker containers
- Deploy to cloud instances
- Configure load balancers