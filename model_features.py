"""Authoritative schema and URL-only mapping for the CSV Random Forest."""

FEATURE_COLUMNS = (
    "NumDots", "SubdomainLevel", "PathLevel", "UrlLength", "NumDash",
    "NumDashInHostname", "AtSymbol", "TildeSymbol", "NumUnderscore",
    "NumPercent", "NumQueryComponents", "NumAmpersand", "NumHash",
    "NumNumericChars", "NoHttps", "RandomString", "IpAddress",
    "DomainInSubdomains", "DomainInPaths", "HttpsInHostname",
    "HostnameLength", "PathLength", "QueryLength", "DoubleSlashInPath",
    "NumSensitiveWords", "EmbeddedBrandName", "PctExtHyperlinks",
    "PctExtResourceUrls", "ExtFavicon", "InsecureForms",
    "RelativeFormAction", "ExtFormAction", "AbnormalFormAction",
    "PctNullSelfRedirectHyperlinks", "FrequentDomainNameMismatch",
    "FakeLinkInStatusBar", "RightClickDisabled", "PopUpWindow",
    "SubmitInfoToEmail", "IframeOrFrame", "MissingTitle",
    "ImagesOnlyInForm", "SubdomainLevelRT", "UrlLengthRT",
    "PctExtResourceUrlsRT", "AbnormalExtFormActionR",
    "ExtMetaScriptLinkRT", "PctExtNullSelfRedirectHyperlinksRT",
)


def to_model_row(features):
    """Build a model row in training order; unknown page-only values are zero."""
    host = features["hostname"]
    full_url = features["full_url"]
    query = features["query"]
    path = features["path"]
    labels = features["host_labels"]
    available = {
        "NumDots": features["dot_count"],
        "SubdomainLevel": 0 if features["has_ip"] else max(0, len(labels) - 2),
        "PathLevel": len([part for part in path.split("/") if part]),
        "UrlLength": features["url_length"],
        "NumDash": features["hyphen_count"],
        "NumDashInHostname": host.count("-"),
        "AtSymbol": features["has_at"],
        "TildeSymbol": int("~" in full_url),
        "NumUnderscore": full_url.count("_"),
        "NumPercent": full_url.count("%"),
        "NumQueryComponents": len([part for part in query.split("&") if part]),
        "NumAmpersand": query.count("&"),
        "NumHash": full_url.count("#"),
        "NumNumericChars": sum(char.isdigit() for char in full_url),
        "NoHttps": 1 - features["https"],
        "IpAddress": features["has_ip"],
        "HostnameLength": len(host),
        "PathLength": len(path),
        "QueryLength": len(query),
        "DoubleSlashInPath": int("//" in path),
        "NumSensitiveWords": features["suspicious_words"],
    }
    return {name: available.get(name, 0) for name in FEATURE_COLUMNS}
