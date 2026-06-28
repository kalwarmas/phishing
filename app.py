
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import joblib
import numpy as np
import re
from urllib.parse import urlparse
import socket
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Load model
print("Loading model...")
try:
    model = joblib.load('model/phishing_model.pkl')
    scaler = joblib.load('model/scaler.pkl')
    feature_names = joblib.load('model/feature_names.pkl')
    print("✓ Model loaded successfully!")
except Exception as e:
    print(f" Error loading model: {e}")
    print("Run: python train_model.py first!")
    exit(1)

def extract_features(url):
    """Extract features from URL"""
    features = {}
    
    try:
        # Add https:// if no protocol
        if not url.startswith(('http://', 'https://')):
            well_known = ['google', 'facebook', 'amazon', 'youtube', 'wikipedia', 
                         'twitter', 'instagram', 'linkedin', 'github', 'microsoft',
                         'apple', 'netflix', 'reddit', 'stackoverflow', 'jinnah']
            if any(domain in url.lower() for domain in well_known):
                url = 'https://' + url
            else:
                url = 'http://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc
        
        features['url_length'] = len(url)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_at'] = url.count('@')
        features['num_question'] = url.count('?')
        features['num_ampersand'] = url.count('&')
        features['num_equal'] = url.count('=')
        
        # IP address detection (only in domain)
        ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
        features['has_ip'] = 1 if ip_pattern.search(domain) else 0
        
        features['has_https'] = 1 if parsed.scheme == 'https' else 0
        
        features['domain_length'] = len(domain)
        features['num_subdomains'] = domain.count('.') - 1 if domain.count('.') > 0 else 0
        
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.cc', '.pw', '.xyz', '.top', '.work']
        features['suspicious_tld'] = 1 if any(tld in url.lower() for tld in suspicious_tlds) else 0
        
        path = parsed.path
        features['path_length'] = len(path)
        
        # Check keywords only in path, not domain
        keywords = ['login', 'verify', 'account', 'banking', 'update',
                   'confirm', 'password', 'signin', 'suspended', 'locked', 'urgent']
        features['has_suspicious_keyword'] = 1 if any(kw in path.lower() for kw in keywords) else 0
        
        special_chars = sum(1 for c in url if not c.isalnum())
        features['special_char_ratio'] = special_chars / len(url) if len(url) > 0 else 0
        
        # Count digits in domain only
        features['num_digits'] = sum(c.isdigit() for c in domain)
        
    except Exception as e:
        print(f"Feature extraction error: {e}")
        return None
    
    return features

def query_whois_server(domain, server, port=43):
    """Query a WHOIS server directly via socket"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((server, port))
        sock.send((domain + "\r\n").encode('utf-8'))
        
        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        
        sock.close()
        return response.decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"Socket error for {server}: {e}")
        return None

def parse_whois_text(text):
    """Parse WHOIS text response into structured data"""
    data = {}
    
    if not text:
        return data
    
    # Common WHOIS field patterns
    patterns = {
        'domain_name': r'Domain Name:\s*(.+)',
        'registrar': r'Registrar:\s*(.+)',
        'whois_server': r'Registrar WHOIS Server:\s*(.+)',
        'creation_date': r'(?:Creation Date|Domain record activated|Created):\s*(.+)',
        'expiration_date': r'(?:Expir.*Date|Registry Expiry Date|Domain expires):\s*(.+)',
        'updated_date': r'(?:Updated Date|Domain record last updated):\s*(.+)',

        'registrant_name': r'Registrant Name:\s*(.+)',
        'registrant_organization': r'(?:Registrant Organization|Organization):\s*(.+)',
        'registrant_address': r'Registrant (?:Street|Address):\s*(.+)',
        'registrant_city': r'Registrant City:\s*(.+)',
        'registrant_state': r'Registrant State/Province:\s*(.+)',
        'registrant_country': r'Registrant Country:\s*(.+)',
        'registrant_email': r'Registrant Email:\s*(.+)',
        'admin_name': r'Admin Name:\s*(.+)',
        'admin_email': r'Admin Email:\s*(.+)',
        'tech_name': r'Tech(?:nical)? Name:\s*(.+)',
        'tech_email': r'Tech(?:nical)? Email:\s*(.+)',
    }
    
    # Extract name servers
    name_servers = []
    for line in text.split('\n'):
        if re.match(r'(?:Name Server|Nameserver|nserver):\s*(.+)', line, re.IGNORECASE):
            match = re.search(r'(?:Name Server|Nameserver|nserver):\s*(.+)', line, re.IGNORECASE)
            if match:
                ns = match.group(1).strip()
                if ns and ns not in name_servers:
                    name_servers.append(ns)
    
    if name_servers:
        data['name_servers'] = name_servers
    
    # Extract other fields
    for key, pattern in patterns.items():
        matches = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
        if matches:
            values = [m.strip() for m in matches if m.strip()]
            if values:
                data[key] = values if len(values) > 1 else values[0]
    
    return data

def get_whois_info(url):
    """Get WHOIS information using multiple methods with API"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.replace('www.', '')
        
        if not domain:
            return {'error': 'Invalid domain'}
        
        print(f"Querying WHOIS for: {domain}")
        
        # Method 1: Use WHOIS API (most reliable)
        whois_data = query_whois_api(domain)
        if whois_data and not whois_data.get('error'):
            print(f"✓ WHOIS data from API: {len(whois_data)} fields")
            return whois_data
        
        # Method 2: Direct socket connection
        print("API failed, trying socket connection...")
        tld = domain.split('.')[-1].lower()
        whois_servers = {
            'com': 'whois.verisign-grs.com',
            'net': 'whois.verisign-grs.com',
            'org': 'whois.pir.org',
            'edu': 'whois.educause.edu',
            'gov': 'whois.dotgov.gov',
            'info': 'whois.afilias.net',
            'biz': 'whois.biz',
        }
        
        whois_server = whois_servers.get(tld, 'whois.iana.org')
        raw_whois = query_whois_server(domain, whois_server)
        
        if raw_whois:
            # Check for referral server
            referral_match = re.search(r'Registrar WHOIS Server:\s*(.+)', raw_whois, re.IGNORECASE)
            if referral_match:
                referral_server = referral_match.group(1).strip()
                print(f"Following referral to: {referral_server}")
                secondary_response = query_whois_server(domain, referral_server)
                if secondary_response:
                    raw_whois = secondary_response
            
            whois_data = parse_whois_text(raw_whois)
            whois_data['raw_data'] = raw_whois
            whois_data['method'] = 'socket'
            
            if whois_data and len(whois_data) > 2:
                print(f"✓ WHOIS data from socket: {len(whois_data)} fields")
                return whois_data
        
        # Method 3: Python-whois library (fallback)
        print("Socket failed, trying python-whois...")
        try:
            import whois as whois_lib
            w = whois_lib.whois(domain)
            
            def safe_get(value):
                if value is None:
                    return None
                if isinstance(value, list):
                    return value[0] if value else None
                return str(value) if value else None
            
            whois_data = {
                'domain_name': safe_get(w.domain_name),
                'registrar': safe_get(w.registrar),
                'creation_date': safe_get(w.creation_date),
                'expiration_date': safe_get(w.expiration_date),
                'updated_date': safe_get(w.updated_date),
                'name_servers': w.name_servers if w.name_servers else [],

                'method': 'python-whois'
            }
            
            if hasattr(w, 'text') and w.text:
                whois_data['raw_data'] = w.text
            
            # Remove None values
            whois_data = {k: v for k, v in whois_data.items() if v}
            
            if len(whois_data) > 2:
                print(f"✓ WHOIS data from python-whois: {len(whois_data)} fields")
                return whois_data
        except Exception as e:
            print(f"python-whois error: {e}")
        
        # All methods failed
        return {
            'error': 'Unable to fetch WHOIS information',
            'note': f'Could not retrieve WHOIS data for {domain}',
            'domain': domain,
            'suggestions': [
                'The domain might have private WHOIS protection',
                'The WHOIS server might be temporarily unavailable',
                'Try again in a few moments'
            ]
        }
        
    except Exception as e:
        print(f"WHOIS error: {e}")
        import traceback
        traceback.print_exc()
        return {
            'error': 'WHOIS lookup failed',
            'message': str(e),
            'note': 'Unable to connect to WHOIS services'
        }

def query_whois_api(domain):
    """Query WHOIS using a free API service"""
    try:
        import requests
        
        # Try multiple free WHOIS APIs
        apis = [
            {
                'name': 'WHOIS.XML API',
                'url': f'https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=at_free&domainName={domain}&outputFormat=json'
            },
            {
                'name': 'RDAP',
                'url': f'https://rdap.org/domain/{domain}'
            }
        ]
        
        for api in apis:
            try:
                print(f"Trying {api['name']}...")
                response = requests.get(api['url'], timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Parse response based on API
                    if 'WhoisRecord' in data:
                        # WHOIS XML API format
                        record = data['WhoisRecord']
                        return {
                            'domain_name': record.get('domainName'),
                            'registrar': record.get('registrarName'),
                            'creation_date': record.get('createdDate'),
                            'expiration_date': record.get('expiresDate'),
                            'updated_date': record.get('updatedDate'),
                            'name_servers': record.get('nameServers', {}).get('hostNames', []),
                            'registrant_name': record.get('registrant', {}).get('name'),
                            'registrant_organization': record.get('registrant', {}).get('organization'),
                            'registrant_country': record.get('registrant', {}).get('country'),

                            'method': 'whois_api'
                        }
                    elif 'entities' in data:
                        # RDAP format
                        return {
                            'domain_name': data.get('ldhName'),

                            'name_servers': [ns.get('ldhName') for ns in data.get('nameservers', [])],
                            'events': data.get('events', []),
                            'method': 'rdap_api'
                        }
            except Exception as e:
                print(f"{api['name']} failed: {e}")
                continue
        
        return None
        
    except Exception as e:
        print(f"API query error: {e}")
        return None

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    """Predict if URL is phishing"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
        
        # Remove trailing slashes
        url = url.rstrip('/')
        
        # Store original URL
        original_url = url
        
        # Smart URL handling - don't add http to well-known domains
        if not url.startswith(('http://', 'https://')):
            well_known = ['google', 'facebook', 'amazon', 'youtube', 'wikipedia', 
                         'twitter', 'instagram', 'linkedin', 'github', 'microsoft',
                         'apple', 'netflix', 'reddit', 'stackoverflow', 'jinnah',
                         'bbc', 'cnn', 'yahoo', 'ebay', 'paypal']
            
            # Check if it's a well-known domain
            is_well_known = any(domain in url.lower().split('/')[0] for domain in well_known)
            
            if is_well_known or url.endswith(('.edu', '.gov', '.org')):
                url = 'https://' + url
            else:
                url = 'http://' + url
        
        print(f"\nAnalyzing: {url} (original: {original_url})")
        
        # Extract features
        features = extract_features(url)
        if features is None:
            return jsonify({'error': 'Error extracting features'}), 400
        
        # Convert to array
        feature_array = np.array([[features[name] for name in feature_names]])
        
        # Scale and predict
        feature_scaled = scaler.transform(feature_array)
        prediction = model.predict(feature_scaled)[0]
        probability = model.predict_proba(feature_scaled)[0]
        
        confidence = float(max(probability))
        result = "Phishing" if prediction == 1 else "Safe"
        
        print(f"Result: {result} ({confidence:.2%})")
        print(f"Features: {features}")
        
        # Get WHOIS
        print("Fetching WHOIS...")
        whois_info = get_whois_info(url)
        
        # Response
        response = {
            'url': url,
            'original_url': original_url,
            'prediction': result,
            'is_phishing': bool(prediction == 1),
            'confidence': confidence,
            'probability_safe': float(probability[0]),
            'probability_phishing': float(probability[1]),
            'features': features,
            'whois': whois_info
        }
        
        return jsonify(response)
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': model is not None,
        'timestamp': datetime.now().isoformat()
    })

if __name__ == '__main__':
    print("\n" + "="*60)
    print("PHISHING URL DETECTOR - Flask Backend")
    print("="*60)
    print("\nServer: http://localhost:5000")
    print("Press Ctrl+C to stop\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)