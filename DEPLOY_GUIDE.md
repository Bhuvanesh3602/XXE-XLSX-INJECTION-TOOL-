# DEPLOYMENT OPTIONS

## LOCAL DEPLOYMENT (Only you can access)
cd d:\Project\xxe-xlsx-tool\xxe-xlsx-tool
.\start.bat

## NETWORK DEPLOYMENT (Others can access from their laptops)

### Quick Network Setup:
```cmd
cd d:\Project\xxe-xlsx-tool\xxe-xlsx-tool
.\deploy-network.bat
```

### Manual Network Setup:
1. Find your IP:
```cmd
ipconfig
```

2. Start backend (already configured for network):
```cmd
cd backend
python app.py
```

3. Start frontend with your IP:
```cmd
cd frontend
set REACT_APP_API_URL=http://YOUR_IP:5000
npm start
```

### Access URLs:
- **You**: http://localhost:3000
- **Others**: http://YOUR_IP:5000 (replace YOUR_IP with actual IP like 192.168.1.100)

### Firewall (if needed):
```cmd
netsh advfirewall firewall add rule name="XXE Frontend" dir=in action=allow protocol=TCP localport=3000
netsh advfirewall firewall add rule name="XXE Backend" dir=in action=allow protocol=TCP localport=5000
```