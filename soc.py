import pandas as pd
import json
import re
import sys
from typing import Dict, List, Tuple, Any


def robust_json_loads(raw_value: Any) -> Dict[str, Any]:
    if raw_value is None or (isinstance(raw_value, float) and pd.isna(raw_value)):
        raise ValueError("empty data_json")

    text = str(raw_value).strip()

    try:
        return json.loads(text)
    except Exception:
        pass

    fixed = text

    if fixed.startswith('"') and fixed.endswith('"'):
        inner = fixed[1:-1]
        try:
            return json.loads(inner)
        except Exception:
            fixed = inner

    if '""' in fixed:
        fixed = fixed.replace('""', '"')

    while fixed.endswith('"'):
        candidate = fixed[:-1]
        try:
            json.loads(candidate)
            fixed = candidate
            break
        except Exception:
            fixed = candidate
            continue

    fixed = re.sub(r'(:\s*)(\d{4}-\d{2}-\d{2})(?=\s*[}\],])', r'\1"\2"', fixed)
    fixed = re.sub(r'(:\s*)(\d{4}-\d{2}-\d{2})(\s*\"?)(?=\s*[}\],])', r'\1"\2"', fixed)

    fixed = re.sub(r'(:\s*)(pending|approved|rejected|active|inactive|success|failed|true|false|null)(?=\s*[}\],"\'])', r'\1"\2"', fixed, flags=re.IGNORECASE)

    fixed = re.sub(r'\"+(?=\s*[}\]])', '"', fixed)

    fixed = re.sub(r'(:\s*)([A-Za-z0-9_\-]+)(?=\s*[}\],])', r'\1"\2"', fixed)

    fixed = re.sub(r'([}\]][\s]*)\"{1,10}$', r'\1', fixed)

    if fixed.count('"') % 2 == 1 and fixed.endswith('"'):
        fixed = fixed[:-1]

    try:
        return json.loads(fixed)
    except Exception as e:
        raw_preview = (text[:200] + '...') if len(text) > 200 else text
        fixed_preview = (fixed[:200] + '...') if len(fixed) > 200 else fixed
        print(f"JSON parsing failed. raw=<{raw_preview}> fixed=<{fixed_preview}> error={e}")
        raise e


class PIIDetector:
    def __init__(self):
        self.phone_pattern = r'^\d{10}$'
        self.aadhar_pattern = r'^\d{12}$'
        self.passport_pattern = r'^[A-Z]\d{7}$'
        self.upi_pattern = r'^[\w\d.]+@[\w\d]+$|^\d{10}@[a-zA-Z]+$'
        self.email_pattern = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$'

    def is_phone_number(self, value) -> bool:
        if value is None:
            return False
        str_value = str(value).strip()
        return bool(re.match(self.phone_pattern, str_value))

    def is_aadhar_number(self, value) -> bool:
        if value is None:
            return False
        clean_value = re.sub(r'\s+', '', str(value).strip())
        return bool(re.match(self.aadhar_pattern, clean_value))

    def is_passport_number(self, value) -> bool:
        if value is None:
            return False
        str_value = str(value).strip()
        return bool(re.match(self.passport_pattern, str_value))

    def is_upi_id(self, value) -> bool:
        if value is None:
            return False
        str_value = str(value).strip()
        return bool(re.match(self.upi_pattern, str_value))

    def is_email(self, value) -> bool:
        if value is None:
            return False
        str_value = str(value).strip()
        return bool(re.match(self.email_pattern, str_value))

    def is_full_name(self, value) -> bool:
        if value is None:
            return False
        str_value = str(value).strip()
        parts = str_value.split()
        return len(parts) >= 2 and all(part.replace('.', '').replace('-', '').isalpha() for part in parts if len(part) > 1)

    def is_complete_address(self, value) -> bool:
        if value is None:
            return False
        str_value = str(value).strip().lower()
        
        words = str_value.split()
        has_numbers = any(char.isdigit() for char in str_value)
        has_multiple_words = len(words) >= 4
        
        address_indicators = ['street', 'road', 'lane', 'colony', 'nagar', 'block', 'sector', 'apartment', 'flat', 'building', 'house']
        has_address_indicator = any(indicator in str_value for indicator in address_indicators)
        
        return has_numbers and has_multiple_words and (has_address_indicator or len(words) >= 6)

    def detect_pii_in_record(self, data: Dict[str, Any]) -> Tuple[bool, Dict[str, str]]:
        standalone_pii = {}
        combinatorial_candidates = {}
        
        for key, value in data.items():
            if value is None or value == "" or str(value).lower() in ['null', 'none', 'nan']:
                continue
                
            if key == 'phone' or self.is_phone_number(value):
                standalone_pii[key] = 'phone'
            elif key == 'aadhar' or self.is_aadhar_number(value):
                standalone_pii[key] = 'aadhar'
            elif key == 'passport' or self.is_passport_number(value):
                standalone_pii[key] = 'passport'
            elif key == 'upi_id' or self.is_upi_id(value):
                standalone_pii[key] = 'upi'
            
            elif key == 'name' and self.is_full_name(value):
                combinatorial_candidates[key] = 'full_name'
            elif key == 'email' and self.is_email(value):
                combinatorial_candidates[key] = 'email'
            elif key == 'address' and self.is_complete_address(value):
                combinatorial_candidates[key] = 'address'
            elif key in ['device_id', 'ip_address'] and str(value).strip():
                str_value = str(value).strip()
                if len(str_value) > 5 and not str_value.lower() in ['null', 'none', 'undefined']:
                    combinatorial_candidates[key] = 'device_info'

        if 'first_name' in data and 'last_name' in data:
            first_name = data.get('first_name')
            last_name = data.get('last_name')
            if (first_name and last_name and 
                str(first_name).strip() and str(last_name).strip() and
                str(first_name).strip().lower() not in ['null', 'none', 'nan'] and
                str(last_name).strip().lower() not in ['null', 'none', 'nan']):
                first_clean = str(first_name).strip()
                last_clean = str(last_name).strip()
                if (first_clean.replace('.', '').replace('-', '').isalpha() and 
                    last_clean.replace('.', '').replace('-', '').isalpha() and
                    len(first_clean) > 1 and len(last_clean) > 1):
                    combinatorial_candidates['first_name'] = 'name_part'
                    combinatorial_candidates['last_name'] = 'name_part'

        has_standalone_pii = len(standalone_pii) > 0
        
        unique_combinatorial_types = set(combinatorial_candidates.values())
        if 'name_part' in unique_combinatorial_types:
            unique_combinatorial_types.discard('name_part')
            unique_combinatorial_types.add('full_name')
        
        has_combinatorial_pii = len(unique_combinatorial_types) >= 2

        detected_fields = {**standalone_pii, **combinatorial_candidates}
        return has_standalone_pii or has_combinatorial_pii, detected_fields

    def redact_value(self, key: str, value, field_type: str) -> str:
        if value is None:
            return value
            
        str_value = str(value)
        
        if field_type == 'phone':
            if len(str_value) == 10 and str_value.isdigit():
                return f"{str_value[:2]}XXXXXX{str_value[-2:]}"
            return "[REDACTED_PHONE]"
            
        elif field_type == 'aadhar':
            clean_value = re.sub(r'\s+', '', str_value)
            if len(clean_value) == 12 and clean_value.isdigit():
                return f"{clean_value[:4]}XXXX{clean_value[-4:]}"
            return "[REDACTED_AADHAR]"
            
        elif field_type == 'passport':
            if len(str_value) >= 8:
                return f"{str_value[0]}XXXXXX{str_value[-1]}"
            return "[REDACTED_PASSPORT]"
            
        elif field_type == 'upi':
            if '@' in str_value:
                parts = str_value.split('@')
                username = parts[0]
                domain = parts[1]
                if len(username) > 3:
                    redacted_username = f"{username[:2]}XXX{username[-1]}"
                else:
                    redacted_username = f"{username[0]}XX"
                return f"{redacted_username}@{domain}"
            return "[REDACTED_UPI]"
            
        elif field_type == 'email':
            if '@' in str_value:
                local, domain = str_value.split('@', 1)
                if len(local) > 3:
                    redacted_local = f"{local[:2]}XXX{local[-1]}"
                else:
                    redacted_local = f"{local[0]}XX"
                return f"{redacted_local}@{domain}"
            return "[REDACTED_EMAIL]"
            
        elif field_type in ['full_name', 'name_part']:
            parts = str_value.split()
            redacted_parts = []
            for part in parts:
                if len(part) > 1:
                    redacted_parts.append(f"{part[0]}XXX")
                else:
                    redacted_parts.append("X")
            return " ".join(redacted_parts)
            
        elif field_type == 'address':
            return "[REDACTED_ADDRESS]"
            
        elif field_type == 'device_info':
            if key == 'ip_address':
                return "[REDACTED_IP]"
            return "[REDACTED_DEVICE]"
            
        return str_value

    def process_record(self, record_id: int, data_json: Dict[str, Any]) -> Dict[str, Any]:
        is_pii, detected_fields = self.detect_pii_in_record(data_json)
        
        if is_pii:
            redacted_data = data_json.copy()
            
            for field, field_type in detected_fields.items():
                if field in redacted_data:
                    redacted_data[field] = self.redact_value(field, redacted_data[field], field_type)
                    
            return {
                'record_id': record_id,
                'redacted_data_json': json.dumps(redacted_data, separators=(',', ':')),
                'is_pii': True
            }
        else:
            return {
                'record_id': record_id,
                'redacted_data_json': json.dumps(data_json, separators=(',', ':')),
                'is_pii': False
            }


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_candidate_name.py input.csv")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = 'redacted_output_candidate_full_name.csv'
    
    try:
        df = pd.read_csv(input_file)
        df.columns = [str(c).strip().lower() for c in df.columns]
        
        detector = PIIDetector()
        
        results = []
        for idx, row in df.iterrows():
            try:
                record_id = row.get('record_id', idx + 1)
                data_json_raw = row.get('data_json')
                if pd.isna(data_json_raw) or data_json_raw is None:
                    raise KeyError('data_json')
                
                try:
                    data_json = json.loads(data_json_raw)
                except Exception:
                    data_json = robust_json_loads(data_json_raw)
                
                result = detector.process_record(record_id, data_json)
                results.append(result)
                
            except Exception as e:
                print(f"Error processing record {row.get('record_id', idx + 1)}: {e}")
                continue
        
        output_df = pd.DataFrame(results)
        output_df.to_csv(output_file, index=False)
        
        print(f"Processing complete. Output saved to {output_file}")
        print(f"Processed {len(results)} records")
        pii_count = sum(1 for r in results if r['is_pii'])
        if len(results) > 0:
            percent = pii_count / len(results) * 100
        else:
            percent = 0.0
        print(f"Found PII in {pii_count} records ({percent:.1f}%)")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()