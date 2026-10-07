import re

_SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def scan_content_with_rules(text, rules):
    if not text or not rules:
        return {"matched_rule_ids": [], "matched_rule_names": [], "confidence_level": "LOW"}
    matched_ids, matched_names, highest = [], [], "LOW"
    for rule in rules:
        rtype = rule.get("rule_type", "REGEX")
        pattern = rule.get("pattern", "")
        matched = False
        try:
            if rtype == "REGEX":
                matched = bool(re.search(pattern, text))
            elif rtype == "DICTIONARY":
                kws = [k.strip() for k in pattern.split(",") if k.strip()]
                matched = any(kw.lower() in text.lower() for kw in kws)
        except re.error:
            continue
        if matched:
            matched_ids.append(rule.get("id"))
            matched_names.append(rule.get("rule_name"))
            sev = rule.get("severity", "LOW")
            if _SEVERITY_ORDER.get(sev, 0) > _SEVERITY_ORDER.get(highest, 0):
                highest = sev
    return {"matched_rule_ids": matched_ids, "matched_rule_names": matched_names,
            "confidence_level": highest if matched_ids else "LOW"}
