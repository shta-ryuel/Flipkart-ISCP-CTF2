# Project Guardian 2.0 - PII Protector Script

import csv
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading

# Custom masking functions for PII protection
def secure_phone(phone_num):
    if len(phone_num) == 10 and phone_num.isdigit():
        return phone_num[:2] + 'XXXXXX' + phone_num[-2:]
    return '[HIDDEN_PHONE]'

def protect_aadhar(aadhar_num):
    aadhar_num = aadhar_num.replace(' ', '')
    if len(aadhar_num) == 12 and aadhar_num.isdigit():
        return aadhar_num[:4] + ' XXXX ' + aadhar_num[-4:]
    return '[HIDDEN_AADHAR]'

def shield_passport(passport_id):
    if re.match(r'^[A-Z]\d{7}$', passport_id):
        return passport_id[0] + 'XXXXXXX'
    return '[HIDDEN_PASSPORT]'

def guard_upi(upi_handle):
    if '@' in upi_handle:
        user_part, bank_part = upi_handle.split('@', 1)
        masked_user = user_part[:2] + 'XXX' if len(user_part) > 3 else user_part
        return masked_user + '@' + bank_part
    return '[HIDDEN_UPI]'

def blur_name(full_name):
    name_parts = re.split(r'\s+', full_name.strip())
    masked_parts = [part[0] + 'XXX' if len(part) > 1 else part for part in name_parts]
    return ' '.join(masked_parts)

def hide_email(email_addr):
    if '@' in email_addr:
        user_part, domain_part = email_addr.split('@', 1)
        masked_user = user_part[:2] + 'XXX' if len(user_part) > 3 else user_part
        return masked_user + '@' + domain_part
    return '[HIDDEN_EMAIL]'

def obscure_address(addr):
    return '[SECURE_ADDRESS]'

def mask_pin(pin):
    if len(pin) == 6 and pin.isdigit():
        return pin[:3] + 'XXX'
    return '[HIDDEN_PIN]'

def check_email(email):
    return bool(re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email))

def is_full_name(name):
    return len(re.split(r'\s+', name.strip())) >= 2

# Process each data record
def process_data_record(data_dict):
    safe_data = data_dict.copy()
    has_pii = False

    pii_checks = {
        'phone': r'^\d{10}$',
        'aadhar': r'^\d{12}$|^(\d{4} ?){3}$',
        'passport': r'^[A-Z]\d{7}$',
        'upi_id': r'.+@.+'
    }
    for key, pattern in pii_checks.items():
        if key in data_dict:
            value = str(data_dict[key]).strip()
            if re.match(pattern, value):
                has_pii = True
                if key == 'phone':
                    safe_data[key] = secure_phone(value)
                elif key == 'aadhar':
                    safe_data[key] = protect_aadhar(value)
                elif key == 'passport':
                    safe_data[key] = shield_passport(value)
                elif key == 'upi_id':
                    safe_data[key] = guard_upi(value)

    if 'contact' in data_dict:
        value = str(data_dict['contact']).strip()
        if re.match(r'^\d{10}$', value):
            safe_data['contact'] = secure_phone(value)
            has_pii = True
        elif check_email(value):
            pass

    name_flag = False
    name_fields = []
    if 'name' in data_dict and is_full_name(data_dict['name']):
        name_flag = True
        name_fields.append('name')
    if 'first_name' in data_dict and 'last_name' in data_dict and data_dict['first_name'].strip() and data_dict['last_name'].strip():
        name_flag = True
        name_fields.extend(['first_name', 'last_name'])

    email_flag = False
    email_fields = []
    if 'email' in data_dict and check_email(data_dict['email']):
        email_flag = True
        email_fields.append('email')
    if 'contact' in data_dict and check_email(str(data_dict['contact'])):
        email_flag = True
        email_fields.append('contact')

    addr_flag = False
    addr_fields = []
    if 'address' in data_dict and data_dict['address'].strip():
        addr_flag = True
        addr_fields.append('address')
    elif all(k in data_dict for k in ['city', 'state', 'pin_code']) and all(data_dict[k].strip() for k in ['city', 'state', 'pin_code']):
        addr_flag = True
        addr_fields.extend(['city', 'state', 'pin_code'])

    device_flag = False
    device_fields = []
    if 'device_id' in data_dict and data_dict['device_id'].strip():
        device_flag = True
        device_fields.append('device_id')
    if 'ip_address' in data_dict and data_dict['ip_address'].strip():
        device_flag = True
        device_fields.append('ip_address')

    if sum([name_flag, email_flag, addr_flag, device_flag]) >= 2:
        has_pii = True
        if name_flag:
            for f in name_fields:
                safe_data[f] = blur_name(data_dict[f])
        if email_flag:
            for f in email_fields:
                safe_data[f] = hide_email(data_dict[f])
        if addr_flag:
            for f in addr_fields:
                if f == 'address':
                    safe_data[f] = obscure_address(data_dict[f])
                elif f == 'city' or f == 'state':
                    safe_data[f] = blur_name(data_dict[f])
                elif f == 'pin_code':
                    safe_data[f] = mask_pin(data_dict[f])
        if device_flag:
            for f in device_fields:
                if f == 'device_id':
                    safe_data[f] = safe_data[f][:4] + 'XXXX' + safe_data[f][-4:] if len(safe_data[f]) > 8 else '[HIDDEN_DEVICE]'
                elif f == 'ip_address':
                    parts = safe_data[f].split('.')
                    if len(parts) == 4:
                        safe_data[f] = '.'.join(parts[:2]) + '.XXX.XXX'

    return json.dumps(safe_data), str(has_pii).lower()

# Batch process CSV and save output
def process_csv(input_file):
    output_file = "redacted_output_candidate_full_name.csv"
    with open(input_file, 'r', encoding='utf-8') as infile, open(output_file, 'w', encoding='utf-8', newline='') as outfile:
        reader = csv.DictReader(infile)
        writer = csv.writer(outfile)
        writer.writerow(['record_id', 'redacted_data_json', 'is_pii'])
        for row in reader:
            record_id = row['record_id']
            try:
                data_dict = json.loads(row['data_json'])
            except json.JSONDecodeError:
                data_dict = {}
            redacted_json, is_pii_val = process_data_record(data_dict)
            writer.writerow([record_id, redacted_json, is_pii_val])
    print(f"Redacted CSV saved to {output_file}")

# Simple HTTP server to handle requests
class PIIHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/secure/pii-filter':
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                data_dict = json.loads(post_data.decode('utf-8'))
                redacted_json, is_pii = process_data_record(data_dict)
                response = json.dumps({"redacted_data": json.loads(redacted_json), "is_pii": is_pii}).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(response)
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

def start_server():
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, PIIHandler)
    print("Starting PII server on port 8000...")
    httpd.serve_forever()

# Main execution
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 detector_full_candidate_name.py <input_csv>")
        sys.exit(1)

    input_file = sys.argv[1]
    process_csv(input_file)

    # Start server in a separate thread
    server_thread = threading.Thread(target=start_server)
    server_thread.daemon = True
    server_thread.start()

    try:
        server_thread.join()  # Keep main thread alive
    except KeyboardInterrupt:
        print("Server stopped by user.")