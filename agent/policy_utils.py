def get_policies_for_exit_point(applicable_policies, exit_point_type):
    return [p for p in (applicable_policies or []) if exit_point_type in (p.get("exit_points") or [])]


def get_exit_point_status(applicable_policies, exit_point_type):
    matching = get_policies_for_exit_point(applicable_policies, exit_point_type)
    if not matching:
        return {"is_governed": False, "effective_action": "OPEN", "content_rules": [],
                "file_types": [], "policy_ids": [], "allowed_files": [], "allowed_locations": []}

    effective_action = "REPORT_ONLY"
    seen_rule_ids, merged_rules = set(), []
    seen_ext, merged_ft = set(), []
    policy_ids = []
    allowed_files, allowed_locations = [], []

    for p in matching:
        policy_ids.append(p.get("policy_id"))
        if p.get("action") == "BLOCK":
            effective_action = "BLOCK"
        for rule in (p.get("content_rules") or []):
            rid = rule.get("id")
            if rid not in seen_rule_ids:
                seen_rule_ids.add(rid)
                merged_rules.append(rule)
        allowed_files.extend(x for x in (p.get("allowed_files") or []) if x not in allowed_files)
        allowed_locations.extend(x for x in (p.get("allowed_locations") or []) if x not in allowed_locations)
        for ft in (p.get("file_types") or []):
            ext = ft.get("extension")
            if ext not in seen_ext:
                seen_ext.add(ext)
                merged_ft.append(ft)

    return {"is_governed": True, "effective_action": effective_action,
            "content_rules": merged_rules, "file_types": merged_ft, "policy_ids": policy_ids,
            "allowed_files": allowed_files, "allowed_locations": allowed_locations,
            "policies": matching}


def _policy_status(policy):
    return {
        "is_governed": True,
        "effective_action": "BLOCK" if policy.get("action") == "BLOCK" else "REPORT_ONLY",
        "policy_ids": [policy.get("policy_id")],
        **{key: policy.get(key) or [] for key in
           ("content_rules", "file_types", "allowed_files", "allowed_locations")},
    }


def _ordered_policies(policies):
    # Numeric API IDs are unique. Use a stable order even for synthetic IDs.
    return sorted(policies, key=lambda p: str(p.get("policy_id")))


def evaluate_policies(status, evaluate):
    """Evaluate policy-local statuses and retain the evidence of the winning decision."""
    policies = status.get("policies")
    if not policies:
        return evaluate(status)

    priority = {"ALLOW": 0, "LOG": 1, "BLOCK": 2}

    def rank(result):
        return priority[result["verdict"]], result.get("reason") != "OUT_OF_SCOPE"

    winner = None
    for policy in _ordered_policies(policies):
        current = _policy_status(policy)
        result = evaluate(current)
        result["policy_id"] = current["policy_ids"][0]
        result["policy_action"] = current["effective_action"]
        if winner is None or rank(result) > rank(winner):
            winner = result
    return winner


def decision_status(status, result):
    """Keep legacy reporting fallbacks for callers without policy attribution."""
    if "policy_id" not in result:
        return status
    return {"policy_ids": [result["policy_id"]], "effective_action": result["policy_action"]}


def unconditional_block(status, *, file_conditions):
    """Find a BLOCK policy whose conditions the channel-wide fast path can enforce."""
    policies = status.get("policies")
    candidates = map(_policy_status, _ordered_policies(policies)) if policies else [status]
    return next((p for p in candidates if p.get("effective_action") == "BLOCK"
                 and not p.get("content_rules")
                 and (not file_conditions or not any(p.get(key) for key in
                      ("file_types", "allowed_files", "allowed_locations")))), None)


def file_in_scope(file_path, file_types):
    """True neu policy khong gioi han loai file, hoac file thuoc mot loai file cua policy."""
    if not file_types:
        return True
    if not file_path or "." not in file_path:
        return False
    ext = file_path.rsplit(".", 1)[-1].lower()
    return any(str(ft.get("extension", "")).lstrip(".").lower() == ext for ft in file_types)

def file_always_blocked(file_path, file_types):
    if not file_path or "." not in file_path:
        return False
    ext = file_path.rsplit(".", 1)[-1].lower()
    return any(str(ft.get("extension", "")).lstrip(".").lower() == ext and ft.get("always_block_regardless_content")
               for ft in file_types)
