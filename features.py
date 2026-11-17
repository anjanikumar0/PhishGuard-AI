import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlparse
import tldextract

extractor = tldextract.TLDExtract(suffix_list_urls=())

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "mcaf.ee", "su.pr", "tiny.cc"
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "zip", "click",
    "work", "support", "surf", "rest", "fit", "cam"
}

SENSITIVE_KEYWORDS = [
    "login", "signin", "verify", "update", "secure", "account",
    "banking", "confirm", "password", "credential", "wallet", "auth"
]

FEATURE_COLUMNS = [
    "url_length", "hostname_length", "path_length", "subdomain_depth",
    "has_ip_address", "has_at_symbol", "hyphen_count_domain", "dot_count",
    "special_char_count", "digit_ratio_domain", "url_entropy",
    "has_redirect_slash", "is_shortened_url", "has_suspicious_tld",
    "sensitive_keyword_count"
]

def calculate_shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())

def has_ip_address(hostname: str) -> int:
    host_only = hostname.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(host_only)
        return 1
    except ValueError:
        return 0

def extract_url_features(url: str) -> tuple[dict, str, str]:
    normalized_url = url.strip()
    if not re.match(r"^https?://", normalized_url, re.IGNORECASE):
        normalized_url = "http://" + normalized_url

    parsed = urlparse(normalized_url)
    ext = extractor(normalized_url)

    hostname = parsed.netloc.lower()
    path = parsed.path
    domain = ext.domain.lower()
    subdomain = ext.subdomain.lower()
    suffix = ext.suffix.lower()
    registrable_domain = f"{domain}.{suffix}" if suffix else domain

    url_length = len(normalized_url)
    hostname_length = len(hostname)
    path_length = len(path)
    subdomain_depth = len([s for s in subdomain.split(".") if s]) if subdomain else 0

    ip_flag = has_ip_address(hostname)
    at_flag = 1 if "@" in normalized_url else 0

    hyphen_count_domain = domain.count("-")
    dot_count = normalized_url.count(".")
    special_char_count = sum(normalized_url.count(c) for c in ["?", "=", "&", "%", "_", "~"])

    digit_count = sum(c.isdigit() for c in domain)
    digit_ratio_domain = round(digit_count / len(domain), 4) if len(domain) > 0 else 0.0

    url_entropy = round(calculate_shannon_entropy(normalized_url), 4)

    last_double_slash = normalized_url.rfind("//")
    has_redirect_slash = 1 if last_double_slash > 7 else 0

    is_shortened_url = 1 if registrable_domain in SHORTENERS else 0
    has_suspicious_tld = 1 if suffix in SUSPICIOUS_TLDS else 0

    target_text = f"{subdomain} {path}".lower()
    sensitive_keyword_count = sum(1 for kw in SENSITIVE_KEYWORDS if kw in target_text)

    features = {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "path_length": path_length,
        "subdomain_depth": subdomain_depth,
        "has_ip_address": ip_flag,
        "has_at_symbol": at_flag,
        "hyphen_count_domain": hyphen_count_domain,
        "dot_count": dot_count,
        "special_char_count": special_char_count,
        "digit_ratio_domain": digit_ratio_domain,
        "url_entropy": url_entropy,
        "has_redirect_slash": has_redirect_slash,
        "is_shortened_url": is_shortened_url,
        "has_suspicious_tld": has_suspicious_tld,
        "sensitive_keyword_count": sensitive_keyword_count,
    }
    return features, normalized_url, registrable_domain
