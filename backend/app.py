from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import zipfile
import tempfile
import shutil
from xxe_generator import XXEGenerator
from xlsx_processor import XLSXProcessor
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)

# Initialize components
xxe_gen = XXEGenerator()
xlsx_proc = XLSXProcessor()

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'message': 'XXE XLSX Tool Backend is running',
        'version': '1.0.0'
    })

@app.route('/api/generate-payloads', methods=['POST'])
def generate_payloads():
    """Generate XXE payloads"""
    try:
        data = request.get_json()
        target_url = data.get('target_url', '')
        collaborator = data.get('collaborator', '')
        attack_type = data.get('attack_type', 'all')
        
        payloads = xxe_gen.generate_payloads(target_url, collaborator, attack_type)
        
        return jsonify({
            'success': True,
            'payloads': payloads,
            'count': len(payloads)
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/inject-xxe', methods=['POST'])
def inject_xxe():
    """Inject XXE payload into XLSX file or ZIP archive"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        payload_type = request.form.get('payload_type', 'doctype')
        payload = request.form.get('payload', '')
        collaborator = request.form.get('collaborator', '')
        
        if not file.filename:
            return jsonify({'error': 'No file selected'}), 400
        
        filename = secure_filename(file.filename)
        temp_path = os.path.join(tempfile.gettempdir(), filename)
        file.save(temp_path)
        
        try:
            # Check if it's a ZIP file
            if filename.lower().endswith('.zip'):
                result = process_zip_file(temp_path, payload_type, payload, collaborator)
            elif filename.lower().endswith('.xlsx'):
                result = xlsx_proc.inject_xxe(temp_path, payload_type, payload, collaborator)
            else:
                return jsonify({'error': 'Unsupported file type. Only XLSX and ZIP files are supported.'}), 400
            
            return jsonify(result)
        
        finally:
            # Cleanup temp file
            if os.path.exists(temp_path):
                os.remove(temp_path)
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def process_zip_file(zip_path, payload_type, payload, collaborator):
    """Process ZIP file containing multiple XLSX files"""
    try:
        temp_dir = tempfile.mkdtemp()
        results = []
        processed_files = []
        
        try:
            # Extract ZIP file
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            
            # Find all XLSX files in the extracted directory
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.lower().endswith('.xlsx'):
                        xlsx_path = os.path.join(root, file)
                        
                        # Process each XLSX file
                        result = xlsx_proc.inject_xxe(xlsx_path, payload_type, payload, collaborator)
                        if result['success']:
                            processed_files.append(file)
                            results.append(result)
            
            if processed_files:
                # Create output ZIP with processed files
                output_filename = f"xxe_batch_{len(processed_files)}_files.zip"
                output_path = os.path.join('processed', output_filename)
                
                os.makedirs('processed', exist_ok=True)
                
                with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as output_zip:
                    for result in results:
                        processed_file_path = os.path.join('processed', result['output_filename'])
                        if os.path.exists(processed_file_path):
                            output_zip.write(processed_file_path, result['output_filename'])
                
                return {
                    'success': True,
                    'output_filename': output_filename,
                    'processed_files': processed_files,
                    'total_files': len(processed_files),
                    'message': f'Successfully processed {len(processed_files)} XLSX files from ZIP archive'
                }
            else:
                return {
                    'success': False,
                    'error': 'No XLSX files found in the ZIP archive'
                }
        
        finally:
            # Cleanup temp directory
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
    
    except Exception as e:
        return {
            'success': False,
            'error': f'Error processing ZIP file: {str(e)}'
        }

@app.route('/api/analyze-file', methods=['POST'])
def analyze_file():
    """Analyze uploaded file structure"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        filename = secure_filename(file.filename)
        temp_path = os.path.join(tempfile.gettempdir(), filename)
        file.save(temp_path)
        
        try:
            if filename.lower().endswith('.zip'):
                analysis = analyze_zip_structure(temp_path)
            elif filename.lower().endswith('.xlsx'):
                analysis = xlsx_proc.analyze_xlsx_structure(temp_path)
            else:
                return jsonify({'error': 'Unsupported file type'}), 400
            
            return jsonify({
                'success': True,
                'analysis': analysis
            })
        
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def analyze_zip_structure(zip_path):
    """Analyze ZIP file structure"""
    analysis = {
        'type': 'zip',
        'xlsx_files': [],
        'total_files': 0,
        'other_files': []
    }
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            file_list = zip_ref.namelist()
            analysis['total_files'] = len(file_list)
            
            for file in file_list:
                if file.lower().endswith('.xlsx'):
                    analysis['xlsx_files'].append(file)
                else:
                    analysis['other_files'].append(file)
    
    except Exception as e:
        analysis['error'] = str(e)
    
    return analysis

@app.route('/api/download/<filename>', methods=['GET'])
def download_file(filename):
    """Download processed file"""
    try:
        file_path = os.path.join('processed', secure_filename(filename))
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True)
        else:
            return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Create processed directory if it doesn't exist
    os.makedirs('processed', exist_ok=True)
    
    port = int(os.environ.get('PORT', 5000))
    
    print("Starting XXE XLSX Tool Backend...")
    print("Supported file types: XLSX, ZIP")
    print(f"Health check: http://localhost:{port}/api/health")
    print(f"API Base URL: http://localhost:{port}/api/")
    
    app.run(debug=False, host='0.0.0.0', port=port)