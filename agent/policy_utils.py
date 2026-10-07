def get_policies_for_exit_point(applicable_policies, exit_point_type):
    return [p for p in (applicable_policies or []) if exit_point_type in (p.get("exit_points") or [])]


def get_exit_point_status(applicable_policies, exit_point_type):
    matching = get_policies_for_exit_point(applicable_policies, exit_point_type)
    if not matching:
        return {"is_governed": False, "effective_action": "OPEN", "content_rules": [],
                "file_types": [], "policy_ids": []}

    effective_action = "REPORT_ONLY"
    seen_rule_ids, merged_rules = set(), []
    seen_ext, merged_ft = set(), []
    policy_ids = []

    for p in matching:
        policy_ids.append(p.get("policy_id"))
        if p.get("action") == "BLOCK":
            effective_action = "BLOCK"
        for rule in (p.get("content_rules") or []):
            rid = rule.get("id")
            if rid not in seen_rule_ids:
                seen_rule_ids.add(rid)
                merged_rules.append(rule)
        for ft in (p.get("file_types") or []):
            ext = ft.get("extension")
            if ext not in seen_ext:
                seen_ext.add(ext)
                merged_ft.append(ft)

    return {"is_governed": True, "effective_action": effective_action,
            "content_rules": merged_rules, "file_types": merged_ft, "policy_ids": policy_ids}


def file_always_blocked(file_path, file_types):
    if not file_path or "." not in file_path:
        return False
    ext = file_path.rsplit(".", 1)[-1].lower()
    return any(ft.get("extension", "").lower() == ext and ft.get("always_block_regardless_content")
               for ft in file_types)
