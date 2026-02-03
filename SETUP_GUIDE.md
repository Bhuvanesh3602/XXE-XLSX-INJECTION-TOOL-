# Modern XXE XLSX Tool Setup Guide

## Features
✅ Modern Tailwind CSS UI with dark theme
✅ Drag & drop file upload (XLSX and ZIP)
✅ Batch processing for ZIP files containing multiple XLSX
✅ Real-time payload generation
✅ Interactive payload viewer with syntax highlighting
✅ Progress tracking and error handling
✅ Responsive design

## Quick Setup

### 1. Install Dependencies
```bash
# Backend
cd backend
pip install Flask Flask-CORS Werkzeug requests

# Frontend
cd ../frontend
npm install
```

### 2. Start Application
```bash
# Terminal 1 - Backend
cd backend
python app.py

# Terminal 2 - Frontend
cd frontend
npm start
```

### 3. Access Application
- Frontend: http://localhost:3000
- Backend API: http://localhost:5000/api/health

## File Support

### XLSX Files
- Single Excel spreadsheet processing
- XML injection into workbook components
- Individual file download

### ZIP Files
- Batch processing of multiple XLSX files
- Automatic extraction and processing
- Combined ZIP output with all processed files

## How It Works

### 1. File Upload
- Drag & drop or click to upload
- Supports .xlsx and .zip files
- Real-time file validation
- File size and type display

### 2. Payload Generation
- Configure collaborator URL for OOB attacks
- Set target URLs for direct attacks
- Choose attack types: DOCTYPE, XInclude, DTD, SVG
- Generate multiple payload variants

### 3. Injection & Results
- View generated payloads with syntax highlighting
- Copy payloads to clipboard
- Inject payloads into files
- Download modified files

## Testing with Postman

### File Upload Test
```
POST http://localhost:5000/api/inject-xxe
Body: form-data
- file: [Upload .xlsx or .zip file]
- payload_type: doctype
- payload: <?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>
- collaborator: https://test.burpcollaborator.net
```

### Expected Response
```json
{
  "success": true,
  "output_filename": "xxe_20241201_sample.xlsx",
  "modified_files": ["xl/workbook.xml"],
  "message": "Successfully injected XXE payload into 1 files"
}
```

## ZIP File Processing

### How ZIP Processing Works
1. Upload ZIP file containing XLSX files
2. Backend extracts all XLSX files
3. Processes each XLSX file individually
4. Creates new ZIP with all processed files
5. Returns batch processing results

### ZIP Response Format
```json
{
  "success": true,
  "output_filename": "xxe_batch_3_files.zip",
  "processed_files": ["file1.xlsx", "file2.xlsx", "file3.xlsx"],
  "total_files": 3,
  "message": "Successfully processed 3 XLSX files from ZIP archive"
}
```

## UI Features

### Modern Design
- Dark gradient background
- Glass morphism effects
- Smooth animations and transitions
- Responsive grid layouts

### Interactive Elements
- Progress steps indicator
- Drag & drop file zones
- Expandable payload cards
- Tabbed results view
- Copy-to-clipboard functionality

### Error Handling
- Real-time validation
- Clear error messages
- Graceful failure recovery
- User-friendly notifications

## Security Features
- File type validation
- Path traversal protection
- Secure filename handling
- Input sanitization
- Clear security warnings

## Troubleshooting

### Common Issues
1. **CORS errors**: Ensure Flask-CORS is installed
2. **File upload fails**: Check file type (.xlsx or .zip only)
3. **Tailwind not working**: Run `npm install` in frontend directory
4. **Backend connection**: Verify backend is running on port 5000

### Success Indicators
✅ Health check returns "healthy"
✅ File upload shows progress
✅ Payloads generate successfully
✅ Files download correctly
✅ UI is responsive and styled