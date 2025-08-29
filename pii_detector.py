import pandas as pd
import json
import re
import ast
from typing import Dict, Tuple

class PIIDetectorRedactor:
    def _init_(self):
        # Patterns for standalone PII
        self.phone_pattern = re.compile(r'\b\d{10}\b')
        self.aadhar_pattern = re.compile(r'\b\d{12}\b')
        self.passport_pattern = re.compile(r'\b[A-Z]{1}\d{7}\b')
        self.upi_pattern = re.compile(r'\b[\w.-]+@[\w.-]+\b|\b\d{10}@\w+\b')
        
        # Combinatorial PII fields
        self.combinatorial_pii_fields = ['name', 'email', 'address', 'device_id', 'ip_address']
        
    def detect_pii(self, data: Dict) -> Tuple[bool, Dict]:
        redacted_data = data.copy()
        has_standalone_pii = False
        combinatorial_pii_count = 0
        combinatorial_fields_present = []
        
        for key, value in data.items():
            if isinstance(value, str):
                # Standalone PII detection
                if key == 'phone' and self.phone_pattern.search(value):
                    has_standalone_pii = True
                    redacted_data[key] = self.redact_phone(value)
                elif key == 'aadhar' and self.aadhar_pattern.search(value):
                    has_standalone_pii = True
                    redacted_data[key] = self.redact_aadhar(value)
                elif key == 'passport' and self.passport_pattern.search(value):
                    has_standalone_pii = True
                    redacted_data[key] = self.redact_passport(value)
                elif key == 'upi_id' and self.upi_pattern.search(value):
                    has_standalone_pii = True
                    redacted_data[key] = self.redact_upi(value)
                
                # Combinatorial PII counting
                if key in self.combinatorial_pii_fields and value.strip():
                    combinatorial_pii_count += 1
                    combinatorial_fields_present.append(key)
        
        # Combinatorial PII redaction
        has_combinatorial_pii = combinatorial_pii_count >= 2
        if has_combinatorial_pii:
            for key in combinatorial_fields_present:
                if key in redacted_data:
                    if key == 'name':
                        redacted_data[key] = self.redact_name(redacted_data[key])
                    elif key == 'email':
                        redacted_data[key] = self.redact_email(redacted_data[key])
                    elif key == 'address':
                        redacted_data[key] = self.redact_address(redacted_data[key])
                    elif key == 'device_id':
                        redacted_data[key] = '[REDACTED_DEVICE_ID]'
                    elif key == 'ip_address':
                        redacted_data[key] = '[REDACTED_IP]'
        
        is_pii = has_standalone_pii or has_combinatorial_pii
        return is_pii, redacted_data
    
    def redact_phone(self, phone: str) -> str:
        return phone[:2] + 'X' * 6 + phone[8:]
    
    def redact_aadhar(self, aadhar: str) -> str:
        return aadhar[:4] + 'X' * 4 + aadhar[8:]
    
    def redact_passport(self, passport: str) -> str:
        return passport[0] + 'X' * 6 + passport[-1] if len(passport) > 1 else '[REDACTED_PASSPORT]'
    
    def redact_upi(self, upi: str) -> str:
        if '@' in upi:
            parts = upi.split('@')
            return parts[0][:2] + 'X' * (len(parts[0]) - 2) + '@' + parts[1]
        return upi[:2] + 'X' * (len(upi) - 4) + upi[-2:]
    
    def redact_name(self, name: str) -> str:
        parts = name.split()
        if len(parts) >= 2:
            return parts[0][0] + 'X' * (len(parts[0]) - 1) + ' ' + parts[-1][0] + 'X' * (len(parts[-1]) - 1)
        return name[0] + 'X' * (len(name) - 1)
    
    def redact_email(self, email: str) -> str:
        parts = email.split('@')
        if len(parts) == 2:
            return parts[0][:2] + 'X' * (len(parts[0]) - 2) + '@' + parts[1]
        return '[REDACTED_EMAIL]'
    
    def redact_address(self, address: str) -> str:
        return '[REDACTED_ADDRESS]'

def fix_json_string(json_str):
    try:
        return json.loads(json_str.replace("'", '"').replace("True", "true").replace("False", "false"))
    except json.JSONDecodeError:
        try:
            return ast.literal_eval(json_str)
        except:
            try:
                fixed_str = re.sub(r'(\w+):\s*([^,\}\]]+)', r'"\1": "\2"', json_str)
                return json.loads(fixed_str.replace("'", '"'))
            except:
                return {}

def process_csv(input_file: str, output_file: str):
    detector = PIIDetectorRedactor()
    df = pd.read_csv(input_file)
    output_data = []
    
    for _, row in df.iterrows():
        record_id = row['record_id']
        data_json = str(row['data_json'])
        
        try:
            data_dict = fix_json_string(data_json)
        except:
            data_dict = {}
        
        is_pii, redacted_data = detector.detect_pii(data_dict)
        redacted_json = json.dumps(redacted_data)
        
        output_data.append({
            'record_id': record_id,
            'redacted_data_json': redacted_json,
            'is_pii': is_pii
        })
    
    output_df = pd.DataFrame(output_data)
    output_df.to_csv(output_file, index=False)
    print(f"Processed {len(output_data)} records. Output saved to {output_file}")

if _name_ == "_main_":
    import sys
    import os
    
    if len(sys.argv) != 2:
        print("Usage: python pii_detector.py <input_csv_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)
    
    base_name = os.path.splitext(os.path.basename(input_file))[0]
    output_file = f"redacted_output_{base_name}.csv"
    process_csv(input_file, output_file)
