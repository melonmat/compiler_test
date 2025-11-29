# json_to_cisco.py

def json_to_cisco(model: dict) -> str:
    """
    JSON Semantic Model -> Cisco IOS 스타일 설정 문자열
    """
    t = model.get("type")

    if t == "acl":
        proto = model["protocol"]
        if model["action"] == "allow":
            return (
                "ip access-list extended ALLOW_TRAFFIC\n"
                f" permit {proto} host {model['src']} host {model['dst']}"
            )
        else:
            return (
                "ip access-list extended BLOCK_TRAFFIC\n"
                f" deny {proto} any any"
            )

    if t == "meter":
        return (
            "class-map match-any HOSTA\n"
            " match ip address HOSTA_ACL\n"
            "policy-map LIMIT_HOSTA\n"
            f" class HOSTA police {model['rate']} conform-action transmit"
        )

    if t == "qos":
        return (
            f"interface vlan{model['Vlan']}\n"
            " priority-queue out\n"
            " mls qos trust cos"
        )

    if t == "connectivity":
        return "Controller installs static routes or ACLs"

    if t == "vlan":
        if model["action"] == "create":
            return f"vlan {model['id']} name {model['name']}"
        else:
            return f"no vlan {model['id']}"

    if t == "route":
        dst = model["dst"]
        network, prefix = dst.split("/")
        netmask = "255.255.255.0" if prefix == "24" else "255.255.255.255"
        return f"ip route {network} {netmask} {model['next_hop']}"

    if t == "monitor":
        return "Use IP SLA or controller probe"

    if t == "backup":
        return "copy running-config startup-config"

    return "! unsupported for cisco"
