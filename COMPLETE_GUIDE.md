# Complete Setup and Testing Guide

## Step 1: Install Prerequisites

### Install Python Dependencies
```bash
cd backend
pip install Flask Flask-CORS Werkzeug requests
```

### Install Node.js Dependencies
```bash
cd frontend
npm install
```

## Step 2: Start the Application

### Terminal 1 - Start Backend
```bash
cd backend
python app.py
```

**Expected Output:**
```
Starting XXE XLSX Tool Backend...
Health check: http://localhost:5000/api/health
 * Running on http://127.0.0.1:5000
 * Debug mode: on
```

### Terminal 2 - Start Frontend
```bash
cd frontend
npm start
```

**Expected Output:**
```
Compiled successfully!
Local:            http://localhost:3000
```

## Step 3: Quick Verification

### Browser Test
1. Open: `http://localhost:3000` (Frontend)
2. Open: `http://localhost:5000/api/health` (Backend API)

Should see:
```json
{"status": "healthy", "message": "XXE XLSX Tool Backend is running", "version": "1.0.0"}
```

## Step 4: Test with Postman

### Test 1: Health Check
- **Method:** GET
- **URL:** `http://localhost:5000/api/health`
- **Click Send**
- **Expected:** Status 200, JSON response with "healthy"

### Test 2: Generate Payloads
- **Method:** POST
- **URL:** `http://localhost:5000/api/generate-payloads`
- **Headers:** `Content-Type: application/json`
- **Body (raw JSON):**
```json
{
  "collaborator": "https://test.example.com",
  "attack_type": "all"
}
```
- **Click Send**
- **Expected:** Status 200, JSON with payloads array

### Test 3: File Upload (Create test XLSX first)
- **Method:** POST
- **URL:** `http://localhost:5000/api/inject-xxe`
- **Body:** form-data
  - `file`: [Upload .xlsx file]
  - `payload_type`: `doctype`
  - `payload`: `test payload`
- **Click Send**
- **Expected:** Status 200, success response

## Step 5: Frontend Testing

1. Go to `http://localhost:3000`
2. Upload an XLSX file
3. Enter collaborator URL: `https://test.example.com`
4. Select attack type: "All Payload Types"
5. Click "Generate Payloads"
6. Click "Inject XXE"
7. Download the modified file

## Step 6: Create Test XLSX File

### Quick Excel File:
1. Open Excel/LibreOffice Calc
2. Add data: A1="Test", B1="Data"
3. Save as "test.xlsx"
4. Use this file for testing

## Troubleshooting

### Backend Issues
- **Port 5000 in use:** Change port in app.py
- **Module not found:** Run `pip install -r requirements.txt`
- **Permission denied:** Run as administrator

### Frontend Issues
- **Port 3000 in use:** Use different port when prompted
- **npm install fails:** Try `npm install --force`
- **Build errors:** Check Node.js version (16+)

### API Connection Issues
- **CORS errors:** Ensure Flask-CORS is installed
- **Connection refused:** Check if backend is running
- **404 errors:** Verify URL paths

## Success Checklist

✅ Backend starts without errors  
✅ Frontend loads at localhost:3000  
✅ Health check returns "healthy"  
✅ Payload generation works in Postman  
✅ File upload works in Postman  
✅ Frontend can upload files  
✅ Payloads are generated in UI  
✅ Modified files can be downloaded  

## Quick Commands Summary

```bash
# Start everything
cd backend && python app.py &
cd frontend && npm start

# Test backend
curl http://localhost:5000/api/health

# Test payload generation
curl -X POST http://localhost:5000/api/generate-payloads \
  -H "Content-Type: application/json" \
  -d '{"collaborator":"https://test.com","attack_type":"all"}'
```