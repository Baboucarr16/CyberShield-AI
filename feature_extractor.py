"""URL-only features shared by the rule detector and training adapter."""
from urllib.parse import urlsplit, urlunsplit
import ipaddress
import re

SUSPICIOUS_WORDS = ["login", "verify", "secure", "bank", "update", "free", "bonus", "gift", "paypal"]


def normalize_url(value):
    if not isinstance(value, str):
        raise ValueError("Enter a valid HTTP or HTTPS URL.")
    value = value.strip()
    if not value or len(value) > 2048 or any(ord(ch) < 32 or ch.isspace() for ch in value) or "\\" in value:
        raise ValueError("Enter a valid HTTP or HTTPS URL.")
    if re.match(r"^[a-z][a-z0-9+.-]*:", value, re.IGNORECASE) and "://" not in value:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if "://" not in value:
        value = "https://" + value
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("Enter a valid HTTP or HTTPS URL.") from exc
    if parsed.scheme.lower() not in ("http", "https") or not host:
        raise ValueError("Enter a valid HTTP or HTTPS URL.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing embedded credentials are not allowed.")
    try:
        ip = ipaddress.ip_address(host)
        normalized_host = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
    except ValueError:
        try:
            normalized_host = host.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError as exc:
            raise ValueError("Enter a valid HTTP or HTTPS URL.") from exc
        labels = normalized_host.split(".")
        valid_label = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
        if (not normalized_host or len(normalized_host) > 253
                or (len(labels) < 2 and normalized_host != "localhost")
                or any(not valid_label.fullmatch(label) for label in labels)
                or re.fullmatch(r"[0-9.]+", normalized_host)):
            raise ValueError("Enter a valid HTTP or HTTPS URL.")
    port = parsed.port
    netloc = normalized_host + (f":{port}" if port is not None else "")
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, parsed.fragment))


def extract_features(url):
    url = normalize_url(url)
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    host_labels = host.split(".")
    path = parsed.path or "/"
    query = parsed.query
    words = sum(word in url.lower() for word in SUSPICIOUS_WORDS)
    try:
        ipaddress.ip_address(host.strip("[]"))
        has_ip = 1
    except ValueError:
        has_ip = 0
    return {
        "url_length": len(url), "https": int(parsed.scheme.lower() == "https"),
        "dot_count": url.count("."), "hyphen_count": url.count("-"),
        "has_at": int("@" in url), "has_ip": has_ip,
        "suspicious_words": words, "domain_length": len(host_labels[-2]) if len(host_labels) > 1 else len(host),
        "hostname": host, "path": path, "query": query, "host_labels": host_labels,
        "full_url": url,
    }
