from urllib.parse import urlparse
import tldextract
import re


# =========================================================
# SUSPICIOUS WORDS
# =========================================================

SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "password",
    "signin",
    "bank",
    "paypal",
    "confirm",
    "security",
    "free",
    "bonus",
    "gift"
]


# =========================================================
# BRAND NAMES
# =========================================================

BRAND_NAMES = [
    "paypal",
    "google",
    "facebook",
    "instagram",
    "microsoft",
    "apple",
    "amazon",
    "netflix",
    "linkedin",
    "bank"
]


# =========================================================
# EXTRACT FEATURES
# =========================================================

def extract_features(url):

    features = {}

    parsed = urlparse(url)

    hostname = parsed.hostname or ""

    path = parsed.path or ""

    query = parsed.query or ""

    url_lower = url.lower()

    hostname_lower = hostname.lower()


    # =====================================================
    # BASIC URL FEATURES
    # =====================================================

    features["url_length"] = len(url)

    features["dot_count"] = url.count(".")

    features["hyphen_count"] = url.count("-")

    features["has_at"] = 1 if "@" in url else 0

    features["has_ip"] = (
        1
        if re.search(
            r"(\d{1,3}\.){3}\d{1,3}",
            url
        )
        else 0
    )


    # =====================================================
    # HTTPS
    # =====================================================

    features["https"] = (
        1
        if parsed.scheme.lower() == "https"
        else 0
    )

    features["no_https"] = (
        1
        if parsed.scheme.lower() != "https"
        else 0
    )


    # =====================================================
    # HOSTNAME FEATURES
    # =====================================================

    features["hostname_length"] = len(hostname)

    features["dash_in_hostname"] = hostname.count("-")

    features["hostname_dots"] = hostname.count(".")


    # =====================================================
    # DOMAIN FEATURES
    # =====================================================

    extracted = tldextract.extract(url)

    domain = extracted.domain or ""

    subdomain = extracted.subdomain or ""

    features["domain_length"] = len(domain)

    features["domain_in_subdomains"] = (
        1
        if domain
        and domain.lower() in subdomain.lower()
        else 0
    )


    # =====================================================
    # PATH FEATURES
    # =====================================================

    features["path_length"] = len(path)

    features["domain_in_path"] = (
        1
        if domain
        and domain.lower() in path.lower()
        else 0
    )

    features["double_slash_in_path"] = (
        1
        if "//" in path
        else 0
    )


    # =====================================================
    # QUERY FEATURES
    # =====================================================

    features["query_length"] = len(query)

    if query:

        query_parts = query.split("&")

        features["query_components"] = len(
            query_parts
        )

    else:

        features["query_components"] = 0


    features["ampersand_count"] = url.count("&")

    features["hash_count"] = url.count("#")

    features["percent_count"] = url.count("%")

    features["underscore_count"] = url.count("_")


    # =====================================================
    # NUMERIC CHARACTERS
    # =====================================================

    features["numeric_chars"] = sum(
        character.isdigit()
        for character in url
    )


    # =====================================================
    # SUSPICIOUS WORDS
    # =====================================================

    found_words = []

    for word in SUSPICIOUS_WORDS:

        if word in url_lower:

            found_words.append(word)


    features["sensitive_words"] = len(
        found_words
    )


    # =====================================================
    # EMBEDDED BRAND NAME
    # =====================================================

    brand_found = False

    for brand in BRAND_NAMES:

        if brand in url_lower:

            brand_found = True

            break


    features["embedded_brand"] = (
        1
        if brand_found
        else 0
    )


    # =====================================================
    # HTTPS INSIDE HOSTNAME
    # =====================================================

    features["https_in_hostname"] = (
        1
        if "https" in hostname_lower
        else 0
    )


    # =====================================================
    # RETURN
    # =====================================================

    return features