import json
import re
import hashlib
import base64
from typing import Dict, Any, List, Set
from datetime import datetime
import copy
import logging

class HARSanitiser:
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialise the HAR sanitiser with optional configuration.
        
        Args:
            config: Dictionary containing configuration options
        """
        self.config = config or {}
        self._setup_logging()
        self._compile_patterns()
        
    def _setup_logging(self):
        """Configure logging for the sanitiser"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def _compile_patterns(self):
        """Compile regex patterns for sensitive data detection"""
        self.patterns = {
            'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            'ip': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            'guid': re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),
            'jwt': re.compile(r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'),
            'phone': re.compile(r'\b\+?1?\d{9,15}\b'),
            'credit_card': re.compile(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b')
        }

    def _hash_value(self, value: str) -> str:
        """
        Create a consistent hash for a value to maintain referential integrity
        
        Args:
            value: String to be hashed
            
        Returns:
            Hashed string value
        """
        return hashlib.sha256(value.encode()).hexdigest()[:12]

    def _is_base64(self, s: str) -> bool:
        """
        Check if a string is base64 encoded
        
        Args:
            s: String to check
            
        Returns:
            Boolean indicating if string is base64 encoded
        """
        try:
            return base64.b64encode(base64.b64decode(s)).decode() == s
        except Exception:
            return False

    def _sanitise_headers(self, headers: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Sanitise HTTP headers
        
        Args:
            headers: List of header dictionaries
            
        Returns:
            Sanitised headers
        """
        sensitive_headers = {
            'authorization', 'cookie', 'set-cookie', 'x-api-key',
            'x-client-id', 'x-session-id', 'user-agent', 'referer',
            'x-forwarded-for', 'etag', 'if-modified-since', 'last-modified'
        }
        
        sanitised = []
        for header in headers:
            name = header['name'].lower()
            if name in sensitive_headers:
                sanitised.append({
                    'name': header['name'],
                    'value': f'[REDACTED-{self._hash_value(header["value"])}]'
                })
            else:
                sanitised.append(header)
        return sanitised

    def _sanitise_query_params(self, url: str) -> str:
        """
        Sanitise URL query parameters
        
        Args:
            url: URL string
            
        Returns:
            Sanitised URL
        """
        if '?' not in url:
            return url

        base_url, query = url.split('?', 1)
        sensitive_params = {'token', 'key', 'password', 'secret', 'auth'}
        tracking_params = {'utm_', 'fbclid', 'gclid', '_ga'}
        
        new_params = []
        for param in query.split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                key_lower = key.lower()
                
                if any(key_lower.startswith(t) for t in tracking_params):
                    continue
                    
                if any(s in key_lower for s in sensitive_params):
                    new_params.append(f'{key}=[REDACTED-{self._hash_value(value)}]')
                else:
                    new_params.append(param)
                    
        return f'{base_url}?{"&".join(new_params)}' if new_params else base_url

    def _sanitise_content(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitise request/response content
        
        Args:
            content: Content dictionary
            
        Returns:
            Sanitised content
        """
        if not content or 'text' not in content:
            return content

        # Handle base64 encoded content
        if self._is_base64(content.get('text', '')):
            return {'text': '[BASE64-CONTENT-REMOVED]'}

        try:
            # Try to parse as JSON
            data = json.loads(content['text'])
            sanitised_data = self._sanitise_json(data)
            content['text'] = json.dumps(sanitised_data)
        except json.JSONDecodeError:
            # If not JSON, apply regex-based sanitisation
            text = content['text']
            for pattern_name, pattern in self.patterns.items():
                text = pattern.sub(f'[REDACTED-{pattern_name}]', text)
            content['text'] = text

        return content

    def _sanitise_json(self, data: Any) -> Any:
        """
        Recursively sanitise JSON data
        
        Args:
            data: JSON data structure
            
        Returns:
            Sanitised JSON data
        """
        if isinstance(data, dict):
            return {k: self._sanitise_json(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._sanitise_json(item) for item in data]
        elif isinstance(data, str):
            # Check for sensitive patterns
            for pattern_name, pattern in self.patterns.items():
                if pattern.search(data):
                    return f'[REDACTED-{pattern_name}-{self._hash_value(data)}]'
            return data
        return data

    def sanitise_har(self, har_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitise the entire HAR file
        
        Args:
            har_data: HAR file data
            
        Returns:
            Sanitised HAR data
        """
        sanitised_har = copy.deepcopy(har_data)
        
        try:
            for entry in sanitised_har['log']['entries']:
                # Sanitise request
                request = entry['request']
                request['url'] = self._sanitise_query_params(request['url'])
                request['headers'] = self._sanitise_headers(request['headers'])
                if 'postData' in request:
                    request['postData'] = self._sanitise_content(request['postData'])

                # Sanitise response
                response = entry['response']
                response['headers'] = self._sanitise_headers(response['headers'])
                if 'content' in response:
                    response['content'] = self._sanitise_content(response['content'])

            # Add sanitisation metadata
            sanitised_har['log']['_meta'] = {
                'sanitised_at': datetime.utcnow().isoformat(),
                'sanitiser_version': '1.0.0'
            }

        except Exception as e:
            self.logger.error(f"Error sanitising HAR file: {str(e)}")
            raise

        return sanitised_har

def main():
    """Main function to demonstrate usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Sanitise HAR files')
    parser.add_argument('input_file', help='Input HAR file path')
    parser.add_argument('output_file', help='Output HAR file path')
    args = parser.parse_args()

    # Read input HAR file
    with open(args.input_file, 'r') as f:
        har_data = json.load(f)

    # Create sanitiser and process HAR file
    sanitiser = HARSanitiser()
    sanitised_har = sanitiser.sanitise_har(har_data)

    # Write sanitised HAR file
    with open(args.output_file, 'w') as f:
        json.dump(sanitised_har, f, indent=2)

if __name__ == '__main__':
    main()
