# json_to_linux.py

def json_to_linux(model: dict) -> str:
    """
    JSON Semantic Model -> Linux 설정 문자열
    """
    t = model.get("type")

    if t == "acl":
        proto = model["protocol"]
        if model["action"] == "allow":
            return (
                "iptables -A INPUT "
                f"-p {proto} -s {model['src']} -d {model['dst']} -j ACCEPT"
            )
        else:
            return f"iptables -A INPUT -p {proto} -j DROP"

    if t == "meter":
        # 매우 단순화된 tc 예시
        return (
            "tc qdisc add dev eth0 root handle 1: htb default 10; "
            f"tc class add dev eth0 parent 1: classid 1:1 htb rate {model['rate']}"
        )

    if t == "qos":
        return (
            "tc class add dev eth0 parent 1: classid 1:10 "
            "htb rate 100mbit prio 0"
        )

    if t == "connectivity":
        # dst 쪽으로 /32 라우트 추가하는 예시
        return f"ip route add {model['dst']}/32 via 10.0.0.254"

    if t == "vlan":
        if model["action"] == "create":
            return (
                f"ip link add link eth0 name eth0.{model['id']} "
                f"type vlan id {model['id']}"
            )
        else:
            return f"ip link delete eth0.{model['id']}"

    if t == "route":
        return f"ip route add {model['dst']} via {model['next_hop']}"

    if t == "monitor":
        return f"ping -c 4 {model['dst']}"

    if t == "backup":
        return "cp /etc/network/interfaces /backup/interfaces.bak"

    return "# unsupported for linux"
