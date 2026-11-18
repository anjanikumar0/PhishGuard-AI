import ipaddress, math, re
from collections import Counter
from urllib.parse import urlparse
import tldextract

extractor = tldextract.TLDExtract(suffix_list_urls=())
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly", "bit.do", "mcaf.ee", "su.pr", "tiny.cc"}
SUSPICIOUS_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "zip", "click", "work", "support", "surf", "rest", "fit", "cam", "autos", "lat", "icu", "buzz", "online", "site", "shop", "live", "monster", "quest"}
SENSITIVE_KEYWORDS = ["login", "signin", "verify", "update", "secure", "account", "banking", "confirm", "password", "credential", "wallet", "auth", "kyc"]
FEATURE_COLUMNS = ["url_length", "hostname_length", "path_length", "subdomain_depth", "has_ip_address", "has_at_symbol", "hyphen_count_domain", "dot_count", "special_char_count", "digit_ratio_domain", "url_entropy", "has_redirect_slash", "is_shortened_url", "has_suspicious_tld", "sensitive_keyword_count"]

def calculate_shannon_entropy(text: str) -> float:
    if not text: return 0.0
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

def normalize_url(url: str) -> str:
    clean = url.strip()
    if not re.match(r"^https?://", clean, re.IGNORECASE):
        clean = "http://" + clean
    return clean

def extract_url_features(url: str) -> tuple[dict, str, str]:
    norm_url = normalize_url(url)
    parsed = urlparse(norm_url)
    ext = extractor(norm_url)
    hostname, path = parsed.netloc.lower(), parsed.path
    domain, subdomain, suffix = ext.domain.lower(), ext.subdomain.lower(), ext.suffix.lower()
    registrable_domain = f"{domain}.{suffix}" if suffix else domain

    features = {
        "url_length": len(norm_url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "subdomain_depth": len([s for s in subdomain.split(".") if s]) if subdomain else 0,
        "has_ip_address": has_ip_address(hostname),
        "has_at_symbol": 1 if "@" in norm_url else 0,
        "hyphen_count_domain": domain.count("-"),
        "dot_count": norm_url.count("."),
        "special_char_count": sum(norm_url.count(c) for c in ["?", "=", "&", "%", "_", "~"]),
        "digit_ratio_domain": round(sum(c.isdigit() for c in domain) / len(domain), 4) if len(domain) > 0 else 0.0,
        "url_entropy": round(calculate_shannon_entropy(norm_url), 4),
        "has_redirect_slash": 1 if norm_url.rfind("//") > 7 else 0,
        "is_shortened_url": 1 if registrable_domain in SHORTENERS else 0,
        "has_suspicious_tld": 1 if suffix in SUSPICIOUS_TLDS else 0,
        "sensitive_keyword_count": sum(1 for kw in SENSITIVE_KEYWORDS if kw in f"{subdomain} {path}".lower()),
    }
    return features, norm_url, registrable_domain
