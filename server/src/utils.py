import re
from urllib.parse import urlparse


def get_domain_details(url: str) -> dict:
    """
    Extract detailed domain information from URL.
    
    Returns:
        dict: {
            'full_domain': str,
            'base_domain': str,
            'subdomain': str,
            'tld': str,
            'protocol': str,
            'port': int or None,
            'is_valid': bool
        }
    """
    result = {
        'full_domain': '',
        'base_domain': '',
        'subdomain': '',
        'tld': '',
        'protocol': '',
        'port': None,
        'is_valid': False
    }
    
    if not url or not isinstance(url, str):
        return result
    
    # Common TLDs for better parsing
    multi_part_tlds = {
        'co.uk', 'com.au', 'org.uk', 'net.au', 'gov.uk',
        'ac.uk', 'edu.au', 'co.nz', 'co.jp', 'com.sg',
        'co.in', 'co.za', 'co.id', 'com.br', 'com.mx',
        'co.kr', 'com.tw', 'com.hk', 'com.cn', 'com.my'
    }
    
    try:
        # Add scheme if missing
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url):
            url = 'http://' + url
        
        parsed = urlparse(url)
        result['protocol'] = parsed.scheme
        
        if not parsed.netloc:
            result['is_valid'] = False
            return result
        
        # Extract domain and port
        domain_parts = parsed.netloc.split(':')
        domain = domain_parts[0]
        
        if len(domain_parts) > 1:
            try:
                result['port'] = int(domain_parts[1])
            except ValueError:
                pass
        
        # Remove www prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        result['full_domain'] = domain
        result['is_valid'] = True
        
        # Parse domain parts
        parts = domain.split('.')
        
        if len(parts) < 2:
            return result
        
        # Check for multi-part TLDs
        if len(parts) >= 3:
            last_two = '.'.join(parts[-2:])
            if last_two in multi_part_tlds:
                # Domain like example.co.uk
                result['tld'] = last_two
                result['base_domain'] = '.'.join(parts[-3:])
                if len(parts) > 3:
                    result['subdomain'] = '.'.join(parts[:-3])
            else:
                # Regular domain like sub.example.com
                result['tld'] = parts[-1]
                result['base_domain'] = '.'.join(parts[-2:])
                if len(parts) > 2:
                    result['subdomain'] = '.'.join(parts[:-2])
        else:
            # Simple domain like example.com
            result['tld'] = parts[-1]
            result['base_domain'] = domain
            result['subdomain'] = ''
        
        return result
        
    except Exception:
        return result

def extract_base_domain(url: str) -> str:
    """Get only the base domain from URL."""
    details = get_domain_details(url)
    return details['base_domain']

def extract_full_domain(url: str) -> str:
    """Get full domain with subdomain."""
    details = get_domain_details(url)
    return details['full_domain']

def is_valid_url_regex(url: str, require_scheme: bool = False) -> bool:
    """
    Check if a string is a valid URL using regex for additional validation.
    
    Args:
        url (str): The string to check
        require_scheme (bool): If True, URL must have http/https scheme
        
    Returns:
        bool: True if valid URL, False otherwise
    """
    # Common URL regex pattern
    pattern = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https:// or ftp://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # or IP
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    # Simpler pattern for URLs without scheme
    pattern_no_scheme = re.compile(
        r'^(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    # Check with scheme
    if re.match(pattern, url):
        return True
    
    # Check without scheme if not required
    if not require_scheme and re.match(pattern_no_scheme, url):
        return True
    
    # Check for other URL types
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        return True
    
    return False