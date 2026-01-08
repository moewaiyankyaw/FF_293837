import json
import os
import threading
from datetime import datetime
from typing import Dict, List, Tuple
import hmac
import hashlib
import requests
import string
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import codecs
import time
import base64
import re
import urllib3
from concurrent.futures import ThreadPoolExecutor
import warnings
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import tempfile

# Fix warning filter
warnings.filterwarnings(
    "ignore",
    message="If 'per_message=False'",
    category=UserWarning
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FIXED_NAME = "HawkXMHM"
FIXED_PASSWORD_PREFIX = "67353272Moe"

REGION_LANG = {
    "TH": "th", "IND": "hi", "BR": "pt"
}

hex_key = "32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533"
key = bytes.fromhex(hex_key)
hex_data = "8J+agCBCbGFjayBBcGlzIEFjY291bnQgR2VuZXJhdG9yIPCfkqsgQnkgQkxBQ0tfQVBJcyB8IE5vdCBGb3IgU2FsZSDwn5Kr"
client_data = base64.b64decode(hex_data).decode('utf-8')
GARENA = "TUgN"

ACCOUNT_RARITY_PATTERNS = {
    "REPEATED_DIGITS_4": [r"(\d)\1{3,}", 3],
    "REPEATED_DIGITS_3": [r"(\d)\1\1(\d)\2\2", 2],
    "SEQUENTIAL_5": [r"(12345|23456|34567|45678|56789)", 4],
    "SEQUENTIAL_4": [r"(0123|1234|2345|3456|4567|5678|6789|9876|8765|7654|6543|5432|4321|3210)", 3],
    "PALINDROME_6": [r"^(\d)(\d)(\d)\3\2\1$", 5],
    "PALINDROME_4": [r"^(\d)(\d)\2\1$", 3],
    "SPECIAL_COMBINATIONS_HIGH": [r"(69|420|1337|007)", 4],
    "SPECIAL_COMBINATIONS_MED": [r"(100|200|300|400|500|666|777|888|999)", 2],
    "QUADRUPLE_DIGITS": [r"(1111|2222|3333|4444|5555|6666|7777|8888|9999|0000)", 4],
    "MIRROR_PATTERN_HIGH": [r"^(\d{2,3})\1$", 3],
    "MIRROR_PATTERN_MED": [r"(\d{2})0\1", 2],
    "GOLDEN_RATIO": [r"1618|0618", 3]
}

app = Flask(__name__)
CORS(app)

# Store generation tasks
generation_tasks: Dict[str, Dict] = {}

class FreeFireRareAccountGenerator:
    def __init__(self):
        self.lock = threading.Lock()
        self.success_counter = 0
        self.rare_counter = 0
        self.running = False
        self.thread_pool = ThreadPoolExecutor(max_workers=100)
        
    def stop_generation(self, task_id=None):
        """Stop the generation process"""
        if task_id:
            if task_id in generation_tasks:
                generation_tasks[task_id]['status'] = 'stopped'
        self.running = False
        
    def check_account_rarity(self, account_data):
        account_id = account_data.get("account_id", "")
        if account_id == "N/A" or not account_id:
            return 0
        
        rarity_score = 0
        detected_patterns = []
        
        for rarity_type, pattern_data in ACCOUNT_RARITY_PATTERNS.items():
            pattern = pattern_data[0]
            score = pattern_data[1]
            if re.search(pattern, account_id):
                rarity_score += score
                detected_patterns.append(rarity_type)
        
        account_id_digits = [int(d) for d in account_id if d.isdigit()]
        
        if len(set(account_id_digits)) == 1 and len(account_id_digits) >= 4:
            rarity_score += 5
            detected_patterns.append("UNIFORM_DIGITS")
        
        if len(account_id_digits) >= 4:
            differences = [account_id_digits[i+1] - account_id_digits[i] for i in range(len(account_id_digits)-1)]
            if len(set(differences)) == 1:
                rarity_score += 4
                detected_patterns.append("ARITHMETIC_SEQUENCE")
        
        if len(account_id) <= 8 and account_id.isdigit() and int(account_id) < 1000000:
            rarity_score += 3
            detected_patterns.append("LOW_ACCOUNT_ID")
        
        return rarity_score

    def generate_random_name(self, base_name):
        exponent_digits = {'0': '⁰', '1': '¹', '2': '²', '3': '³', '4': '⁴', '5': '⁵', '6': '⁶', '7': '⁷', '8': '⁸', '9': '⁹'}
        number = random.randint(1, 99999)
        number_str = f"{number:05d}"
        exponent_str = ''.join(exponent_digits[digit] for digit in number_str)
        return f"{base_name[:7]}{exponent_str}"
    
    def generate_custom_password(self, prefix):
        garena_decoded = base64.b64decode(GARENA).decode('utf-8')
        characters = string.ascii_uppercase + string.digits
        random_part1 = ''.join(random.choice(characters) for _ in range(5))
        random_part2 = ''.join(random.choice(characters) for _ in range(5))
        return f"{prefix}_{random_part1}_{garena_decoded}_{random_part2}"
    
    def EnC_Vr(self, N):
        if N < 0: 
            return b''
        H = []
        while True:
            BesTo = N & 0x7F 
            N >>= 7
            if N: 
                BesTo |= 0x80
            H.append(BesTo)
            if not N: 
                break
        return bytes(H)
    
    def CrEaTe_VarianT(self, field_number, value):
        field_header = (field_number << 3) | 0
        return self.EnC_Vr(field_header) + self.EnC_Vr(value)
    
    def CrEaTe_LenGTh(self, field_number, value):
        field_header = (field_number << 3) | 2
        encoded_value = value.encode() if isinstance(value, str) else value
        return self.EnC_Vr(field_header) + self.EnC_Vr(len(encoded_value)) + encoded_value
    
    def CrEaTe_ProTo(self, fields):
        packet = bytearray()    
        for field, value in fields.items():
            if isinstance(value, dict):
                nested_packet = self.CrEaTe_ProTo(value)
                packet.extend(self.CrEaTe_LenGTh(field, nested_packet))
            elif isinstance(value, int):
                packet.extend(self.CrEaTe_VarianT(field, value))           
            elif isinstance(value, str) or isinstance(value, bytes):
                packet.extend(self.CrEaTe_LenGTh(field, value))           
        return packet
    
    def E_AEs(self, Pc):
        Z = bytes.fromhex(Pc)
        aes_key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
        iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_data = pad(Z, AES.block_size)
        encrypted = cipher.encrypt(padded_data)
        return encrypted

    def encrypt_api(self, plain_text):
        plain_text = bytes.fromhex(plain_text)
        aes_key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
        iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_data = pad(plain_text, AES.block_size)
        encrypted = cipher.encrypt(padded_data)
        return encrypted.hex()
    
    def create_acc(self, region, account_name, password_prefix, is_ghost=False):
        try:
            password = self.generate_custom_password(password_prefix)
            data = f"password={password}&client_type=2&source=2&app_id=100067"
            message = data.encode('utf-8')
            signature = hmac.new(key, message, hashlib.sha256).hexdigest()
            
            url = "https://100067.connect.garena.com/oauth/guest/register"
            headers = {
                "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
                "Authorization": "Signature " + signature,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept-Encoding": "gzip",
                "Connection": "Keep-Alive"
            }
            
            response = requests.post(url, headers=headers, data=data, timeout=30, verify=False)
            response.raise_for_status()
            
            if 'uid' in response.json():
                uid = response.json()['uid']
                return self.token(uid, password, region, account_name, password_prefix, is_ghost)
            return None
        except Exception as e:
            return None
    
    def token(self, uid, password, region, account_name, password_prefix, is_ghost=False):
        try:
            url = "https://100067.connect.garena.com/oauth/guest/token/grant"
            headers = {
                "Accept-Encoding": "gzip",
                "Connection": "Keep-Alive",
                "Content-Type": "application/x-www-form-urlencoded",
                "Host": "100067.connect.garena.com",
                "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
            }
            body = {
                "uid": uid,
                "password": password,
                "response_type": "token",
                "client_type": "2",
                "client_secret": key,
                "client_id": "100067"
            }
            
            response = requests.post(url, headers=headers, data=body, timeout=30, verify=False)
            response.raise_for_status()
            
            if 'open_id' in response.json():
                open_id = response.json()['open_id']
                access_token = response.json()["access_token"]
                refresh_token = response.json()['refresh_token']
                
                result = self.encode_string(open_id)
                field = self.to_unicode_escaped(result['field_14'])
                field = codecs.decode(field, 'unicode_escape').encode('latin1')
                return self.Major_Regsiter(access_token, open_id, field, uid, password, region, account_name, password_prefix, is_ghost)
            return None
        except Exception as e:
            return None
    
    def encode_string(self, original):
        keystream = [0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37,
                     0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30]
        encoded = ""
        for i in range(len(original)):
            orig_byte = ord(original[i])
            key_byte = keystream[i % len(keystream)]
            result_byte = orig_byte ^ key_byte
            encoded += chr(result_byte)
        return {"open_id": original, "field_14": encoded}
    
    def to_unicode_escaped(self, s):
        return ''.join(c if 32 <= ord(c) <= 126 else f'\\u{ord(c):04x}' for c in s)
    
    def Major_Regsiter(self, access_token, open_id, field, uid, password, region, account_name, password_prefix, is_ghost=False):
        try:
            if is_ghost:
                url = "https://loginbp.ggblueshark.com/MajorRegister"
            else:
                url = "https://loginbp.common.ggbluefox.com/MajorRegister"
            
            name = self.generate_random_name(account_name)
            
            headers = {
                "Accept-Encoding": "gzip",
                "Authorization": "Bearer",   
                "Connection": "Keep-Alive",
                "Content-Type": "application/x-www-form-urlencoded",
                "Expect": "100-continue",
                "Host": "loginbp.ggblueshark.com" if is_ghost else "loginbp.common.ggbluefox.com",
                "ReleaseVersion": "OB51",
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
                "X-GA": "v1 1",
                "X-Unity-Version": "2018.4."
            }

            lang_code = "pt" if is_ghost else REGION_LANG.get(region.upper(), "en")
            payload = {
                1: name,
                2: access_token,
                3: open_id,
                5: 102000007,
                6: 4,
                7: 1,
                13: 1,
                14: field,
                15: lang_code,
                16: 1,
                17: 1
            }

            payload_bytes = self.CrEaTe_ProTo(payload)
            encrypted_payload = self.E_AEs(payload_bytes.hex())
            
            response = requests.post(url, headers=headers, data=encrypted_payload, verify=False, timeout=30)
            
            if response.status_code == 200:
                login_result = self.perform_major_login(uid, password, access_token, open_id, region, is_ghost)
                account_id = login_result.get("account_id", "N/A")
                jwt_token = login_result.get("jwt_token", "")
                
                account_data = {
                    "uid": uid, 
                    "password": password, 
                    "name": name, 
                    "region": "GHOST" if is_ghost else region, 
                    "status": "success",
                    "account_id": account_id,
                    "jwt_token": jwt_token
                }
                
                return account_data
            else:
                return None
        except Exception as e:
            return None
    
    def perform_major_login(self, uid, password, access_token, open_id, region, is_ghost=False):
        try:
            lang = "pt" if is_ghost else REGION_LANG.get(region.upper(), "en")
            
            payload_parts = [
                b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02',
                lang.encode("ascii"),
                b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
            ]
            
            payload = b''.join(payload_parts)
            
            if is_ghost:
                url = "https://loginbp.ggblueshark.com/MajorLogin"
            else:
                url = "https://loginbp.common.ggbluefox.com/MajorLogin"
            
            headers = {
                "Accept-Encoding": "gzip",
                "Authorization": "Bearer",
                "Connection": "Keep-Alive",
                "Content-Type": "application/x-www-form-urlencoded",
                "Expect": "100-continue",
                "Host": "loginbp.ggblueshark.com" if is_ghost else "loginbp.common.ggbluefox.com",
                "ReleaseVersion": "OB51",
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
                "X-GA": "v1 1",
                "X-Unity-Version": "2018.4.11f1"
            }

            data = payload
            data = data.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode())
            data = data.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())
            
            d = self.encrypt_api(data.hex())
            final_payload = bytes.fromhex(d)

            response = requests.post(url, headers=headers, data=final_payload, verify=False, timeout=30)
            
            if response.status_code == 200 and len(response.text) > 10:
                jwt_start = response.text.find("eyJ")
                if jwt_start != -1:
                    jwt_token = response.text[jwt_start:]
                    second_dot = jwt_token.find(".", jwt_token.find(".") + 1)
                    if second_dot != -1:
                        jwt_token = jwt_token[:second_dot + 44]
                        
                        account_id = self.decode_jwt_token(jwt_token)
                        return {"account_id": account_id, "jwt_token": jwt_token}
            
            return {"account_id": "N/A", "jwt_token": ""}
        except Exception as e:
            return {"account_id": "N/A", "jwt_token": ""}
    
    def decode_jwt_token(self, jwt_token):
        try:
            parts = jwt_token.split('.')
            if len(parts) >= 2:
                payload_part = parts[1]
                padding = 4 - len(payload_part) % 4
                if padding != 4:
                    payload_part += '=' * padding
                decoded = base64.urlsafe_b64decode(payload_part)
                data = json.loads(decoded)
                account_id = data.get('account_id') or data.get('external_id')
                if account_id:
                    return str(account_id)
        except Exception:
            pass
        return "N/A"
    
    def generate_account_wrapper(self, args):
        """Wrapper function for thread pool execution with retry logic"""
        region, account_name, password_prefix, is_ghost, retry_count, task_id = args
        max_retries = 3
        
        for attempt in range(max_retries):
            if task_id in generation_tasks and generation_tasks[task_id]['status'] == 'stopped':
                return None
                
            try:
                account_result = self.create_acc(region, account_name, password_prefix, is_ghost)
                if account_result:
                    with self.lock:
                        self.success_counter += 1
                        current_count = self.success_counter

                    rarity_score = self.check_account_rarity(account_result)
                    
                    return {
                        "account": account_result,
                        "rarity_score": rarity_score,
                        "count": current_count,
                        "attempts": attempt + 1
                    }
            except Exception:
                pass
            
            # Small delay between retries
            time.sleep(0.1 * (attempt + 1))
        
        return None

generator = FreeFireRareAccountGenerator()

# GET-ONLY API Routes

@app.route('/api/generate', methods=['GET'])
def generate_accounts():
    """Generate Free Fire accounts - GET version"""
    try:
        # Get parameters from query string
        region = request.args.get('region', 'TH').upper()
        count_str = request.args.get('count', '1')
        ghost_mode = request.args.get('ghost', 'false').lower() == 'true'
        
        # Validate count
        try:
            count = int(count_str)
        except ValueError:
            return jsonify({"error": "Count must be a number"}), 400
            
        if region not in ['TH', 'IND', 'BR', 'GHOST']:
            return jsonify({"error": "Invalid region. Use TH, IND, BR, or GHOST"}), 400
            
        if count < 1 or count > 9999:
            return jsonify({"error": "Count must be between 1 and 9999"}), 400
        
        # Create task
        task_id = f"task_{int(time.time())}_{random.randint(1000, 9999)}"
        generation_tasks[task_id] = {
            'region': "BR" if ghost_mode else region,
            'count': count,
            'name': FIXED_NAME,
            'password': FIXED_PASSWORD_PREFIX,
            'is_ghost': ghost_mode,
            'status': 'running',
            'start_time': time.time(),
            'generated': 0,
            'rare_found': 0,
            'failed_attempts': 0,
            'total_attempts': 0,
            'accounts': [],
            'accounts_by_score': {}
        }
        
        # Start generation in background thread
        threading.Thread(target=run_generation, args=(task_id,)).start()
        
        return jsonify({
            "success": True,
            "task_id": task_id,
            "message": f"Started generating {count} accounts for region {region}",
            "ghost_mode": ghost_mode,
            "status_url": f"/api/status?task_id={task_id}",
            "stop_url": f"/api/stop?task_id={task_id}",
            "download_url": f"/api/download?task_id={task_id}"
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get generation task status - GET version"""
    task_id = request.args.get('task_id')
    
    if not task_id:
        return jsonify({"error": "task_id parameter is required"}), 400
        
    if task_id not in generation_tasks:
        return jsonify({"error": "Task not found"}), 404
    
    task = generation_tasks[task_id]
    elapsed = time.time() - task['start_time']
    
    return jsonify({
        "task_id": task_id,
        "status": task['status'],
        "region": task['region'],
        "ghost_mode": task['is_ghost'],
        "progress": {
            "requested": task['count'],
            "generated": task['generated'],
            "percentage": round((task['generated'] / task['count'] * 100), 2) if task['count'] > 0 else 0
        },
        "statistics": {
            "rare_accounts": task['rare_found'],
            "total_attempts": task['total_attempts'],
            "failed_attempts": task['failed_attempts']
        },
        "performance": {
            "elapsed_time": f"{elapsed:.2f}s",
            "speed": f"{task['generated']/elapsed:.2f} accounts/sec" if elapsed > 0 else "0"
        },
        "start_time": datetime.fromtimestamp(task['start_time']).isoformat()
    }), 200

@app.route('/api/stop', methods=['GET'])
def stop_generation():
    """Stop a generation task - GET version"""
    task_id = request.args.get('task_id')
    
    if not task_id:
        return jsonify({"error": "task_id parameter is required"}), 400
        
    if task_id not in generation_tasks:
        return jsonify({"error": "Task not found"}), 404
    
    generator.stop_generation(task_id)
    
    return jsonify({
        "success": True,
        "message": f"Generation task {task_id} stopped",
        "final_stats": {
            "generated": generation_tasks[task_id]['generated'],
            "rare_accounts": generation_tasks[task_id]['rare_found']
        }
    }), 200

@app.route('/api/download', methods=['GET'])
def download_accounts():
    """Download generated accounts - GET version"""
    task_id = request.args.get('task_id')
    
    if not task_id:
        return jsonify({"error": "task_id parameter is required"}), 400
        
    if task_id not in generation_tasks:
        return jsonify({"error": "Task not found"}), 404
    
    task = generation_tasks[task_id]
    
    if task['status'] != 'completed' and task['status'] != 'stopped':
        return jsonify({"error": "Task not completed yet"}), 400
    
    if not task['accounts']:
        return jsonify({"error": "No accounts generated"}), 404
    
    # Create temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
        # Group accounts by score
        output_data = {}
        for score, accounts in task['accounts_by_score'].items():
            output_data[f"score_{score}"] = accounts
        
        json.dump(output_data, f, indent=2, ensure_ascii=False)
        file_path = f.name
    
    # Send file
    try:
        return send_file(
            file_path,
            as_attachment=True,
            download_name=f"freefire_accounts_{task_id}.json",
            mimetype='application/json'
        )
    finally:
        # Clean up temp file after sending
        os.unlink(file_path)

@app.route('/api/regions', methods=['GET'])
def get_regions():
    """Get available regions"""
    return jsonify({
        "regions": [
            {"code": "TH", "name": "Thailand", "language": "th"},
            {"code": "IND", "name": "Indonesia", "language": "hi"},
            {"code": "BR", "name": "Brazil", "language": "pt"},
            {"code": "GHOST", "name": "Ghost Mode", "language": "pt", "note": "Special mode"}
        ]
    }), 200

@app.route('/api/stats', methods=['GET'])
def get_global_stats():
    """Get global statistics"""
    return jsonify({
        "total_generated": generator.success_counter,
        "active_tasks": len([t for t in generation_tasks.values() if t['status'] == 'running']),
        "completed_tasks": len([t for t in generation_tasks.values() if t['status'] == 'completed']),
        "thread_pool_workers": generator.thread_pool._max_workers
    }), 200

@app.route('/api/generate_single', methods=['GET'])
def generate_single_account():
    """Generate a single account - GET version"""
    try:
        region = request.args.get('region', 'TH').upper()
        ghost_mode = request.args.get('ghost', 'false').lower() == 'true'
        
        if region not in ['TH', 'IND', 'BR', 'GHOST']:
            return jsonify({"error": "Invalid region"}), 400
        
        # Generate single account
        region_code = "BR" if ghost_mode else region
        account_result = generator.create_acc(region_code, FIXED_NAME, FIXED_PASSWORD_PREFIX, ghost_mode)
        
        if not account_result:
            return jsonify({"error": "Failed to generate account"}), 500
        
        rarity_score = generator.check_account_rarity(account_result)
        
        return jsonify({
            "success": True,
            "account": account_result,
            "rarity_score": rarity_score,
            "rarity_level": "Rare" if rarity_score > 1 else "Normal"
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "FreeFire Account Generator API"
    }), 200

@app.route('/')
def index():
    """API documentation"""
    return jsonify({
        "service": "FreeFire Account Generator API",
        "version": "1.0",
        "description": "All endpoints use GET method only",
        "endpoints": {
            "GET /api/generate": "Generate multiple accounts. Parameters: region, count, ghost",
            "GET /api/generate_single": "Generate single account. Parameters: region, ghost",
            "GET /api/status": "Check generation status. Parameter: task_id",
            "GET /api/stop": "Stop generation. Parameter: task_id",
            "GET /api/download": "Download generated accounts. Parameter: task_id",
            "GET /api/regions": "Get available regions",
            "GET /api/stats": "Get global statistics",
            "GET /health": "Health check"
        },
        "parameters": {
            "region": "TH, IND, BR, or GHOST (default: TH)",
            "count": "1-9999 (default: 1)",
            "ghost": "true/false (default: false)",
            "task_id": "Task ID from generation response"
        },
        "examples": {
            "generate": "/api/generate?region=TH&count=10&ghost=false",
            "single": "/api/generate_single?region=IND",
            "status": "/api/status?task_id=task_1234567890_1234"
        },
        "defaults": {
            "name": FIXED_NAME,
            "password_prefix": FIXED_PASSWORD_PREFIX
        }
    }), 200

def run_generation(task_id):
    """Background generation function"""
    task = generation_tasks.get(task_id)
    if not task:
        return
    
    region = task['region']
    count = task['count']
    name = task['name']
    password = task['password']
    is_ghost = task['is_ghost']
    
    try:
        generator.running = True
        generator.success_counter = 0
        
        accounts_by_score = {}
        pending_accounts = count
        
        # Submit initial batch of tasks
        futures = []
        for i in range(min(count, 10)):
            args = (region, name, password, is_ghost, 0, task_id)
            future = generator.thread_pool.submit(generator.generate_account_wrapper, args)
            futures.append((future, i))
            with generator.lock:
                task['total_attempts'] += 1
        
        processed_futures = 0
        
        while pending_accounts > 0 and generator.running:
            # Check if task was stopped
            if task['status'] == 'stopped':
                break
            
            # Process completed futures
            for future, index in futures[:]:
                if future.done():
                    processed_futures += 1
                    futures.remove((future, index))
                    
                    result = future.result()
                    
                    if result:
                        # Successful generation
                        account_data = result['account']
                        score = result["rarity_score"]
                        
                        with generator.lock:
                            task['generated'] += 1
                            pending_accounts -= 1
                            
                            # Store account
                            task['accounts'].append(account_data)
                            
                            # Group by score
                            if score not in accounts_by_score:
                                accounts_by_score[score] = []
                                task['accounts_by_score'][score] = []
                            
                            accounts_by_score[score].append(account_data)
                            task['accounts_by_score'][score].append(account_data)
                        
                        # Update rare counter if score > 1
                        if score > 1:
                            with generator.lock:
                                task['rare_found'] += 1
                    else:
                        # Failed generation
                        with generator.lock:
                            task['failed_attempts'] += 1
                            # Add new task to replace failed one
                            args = (region, name, password, is_ghost, 0, task_id)
                            new_future = generator.thread_pool.submit(generator.generate_account_wrapper, args)
                            futures.append((new_future, len(futures)))
                            task['total_attempts'] += 1
            
            # Submit more tasks if we have capacity
            while len(futures) < 10 and pending_accounts > 0:
                args = (region, name, password, is_ghost, 0, task_id)
                future = generator.thread_pool.submit(generator.generate_account_wrapper, args)
                futures.append((future, len(futures)))
                with generator.lock:
                    task['total_attempts'] += 1
            
            # Small delay to prevent busy waiting
            time.sleep(0.1)
        
        # Wait for any remaining futures
        for future, index in futures:
            if not future.done():
                try:
                    future.result(timeout=5)
                except:
                    pass
        
        task['status'] = 'completed'
        generator.stop_generation()
        
    except Exception as e:
        task['status'] = 'error'
        task['error'] = str(e)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)