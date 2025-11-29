# json_to_p4.py

def json_to_p4(model: dict) -> str:
    """
    JSON Semantic Model -> P4/OpenFlow 스타일 설정 문자열
    (논문/보고서용 예시 형식)
    """
    t = model.get("type")

    if t == "acl":
        if model["action"] == "allow":
            return (
                "acl_table: match={"
                f"'src':'{model['src']}',"
                f"'dst':'{model['dst']}',"
                f"'proto':'{model['protocol']}'"
                "}, action=allow"
            )
        else:
            return (
                "acl_table: match={"
                f"'proto':'{model['protocol']}'"
                "}, action=deny"
            )

    if t == "meter":
        return (
            "meter_table: match={"
            f"'src':'{model['host']}'"
            "}, action={'set_rate':'" + model["rate"] + "'}"
        )

    if t == "qos":
        return (
            "qos_table: match={"
            f"'Vlan':{model['Vlan']}"
            "}, action={'set_priority':'high'}"
        )

    if t == "connectivity":
        return (
            "flow_table: match={"
            f"'src':'{model['src']}',"
            f"'dst':'{model['dst']}'"
            "}, action='forward', path=['SW1','SW3']"
        )

    if t == "vlan":
        if model["action"] == "create":
            return "VLAN setup via P4 metadata (optional)"
        else:
            return "Remove VLAN metadata in tables"

    if t == "route":
        return (
            "flow_table: match={"
            f"'dst':'{model['dst']}'"
            "}, action='forward'"
        )

    if t == "monitor":
        return "monitor_table: timestamps/counters to measure RTT"

    if t == "backup":
        return "Save controller switch state to JSON/YAML"

    return "// unsupported for P4/OpenFlow"
