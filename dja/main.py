# main.py

from lark import Lark, Transformer, UnexpectedInput
from pathlib import Path
import json
import sys
import argparse

from json_to_linux import json_to_linux
from json_to_p4 import json_to_p4
from json_to_cisco import json_to_cisco

# -----------------------------
# 1) Lark 파서 준비
# -----------------------------
GRAMMAR = Path("intentlang.lark").read_text(encoding="utf-8")
parser = Lark(GRAMMAR, parser="lalr", start="start")

# host명 -> IP 매핑
HOST_MAP = {
    "A": "10.0.0.1",
    "B": "10.0.0.2",
    "hostA": "10.0.0.1",
    "hostB": "10.0.0.2",
}


# -----------------------------
# 2) IntentLang → JSON Semantic Model
# -----------------------------
class IntentToJSON(Transformer):
    def NUMBER(self, token):
        return int(token)

    def IDENT(self, token):
        return str(token)

    def IPADDR(self, token):
        return str(token)

    # host, endpoint
    def host(self, items):
        (name,) = items
        return HOST_MAP.get(name, name)

    def endpoint(self, items):
        return items[0]

    # 1. allow tcp from A to B
    def allow_stmt(self, items):
        src, dst = items
        return {
            "type": "acl",
            "action": "allow",
            "protocol": "tcp",
            "src": src,
            "dst": dst,
        }

    # 2. block icmp
    def block_stmt(self, items):
        return {
            "type": "acl",
            "action": "deny",
            "protocol": "icmp",
        }

    # 3. limit bandwidth 10Mbps for hostA
    def limit_stmt(self, items):
        rate, host_ip = items
        return {
            "type": "meter",
            "host": host_ip,
            "rate": f"{rate}Mbps",
        }

    # 4. assign qos high to vlan10
    def qos_stmt(self, items):
        (vlan_id,) = items
        return {
            "type": "qos",
            "Vlan": vlan_id,
            "priority": "high",
        }

    # 5. ensure connectivity between hostA and hostB
    def connectivity_stmt(self, items):
        src, dst = items
        return {
            "type": "connectivity",
            "src": src,
            "dst": dst,
        }

    # 6. create vlan 20 name Engineering
    def create_vlan_stmt(self, items):
        vid, name = items
        return {
            "type": "vlan",
            "id": vid,
            "name": name,
            "action": "create",
        }

    # 7. delete vlan 10
    def delete_vlan_stmt(self, items):
        (vid,) = items
        return {
            "type": "vlan",
            "id": vid,
            "action": "delete",
        }

    # 8. set route 10.0.0.0/24 via 192.168.1.1
    def route_stmt(self, items):
        dst, next_hop = items
        return {
            "type": "route",
            "dst": dst,
            "next_hop": next_hop,
        }

    # 9. monitor latency between hostA and hostB
    def monitor_stmt(self, items):
        src, dst = items
        return {
            "type": "monitor",
            "metric": "latency",
            "src": src,
            "dst": dst,
        }

    # 10. backup configuration now
    def backup_stmt(self, items):
        return {
            "type": "backup",
            "action": "now",
        }

    def stmt(self, items):
        return items[0]

    def start(self, items):
        return items


def compile_intent(code: str):
    try:
        tree = parser.parse(code)
    except UnexpectedInput as e:
        print("=== Parse Error ===", file=sys.stderr)
        print(e.get_context(code), file=sys.stderr)
        raise

    json_models = IntentToJSON().transform(tree)
    return json_models


# -----------------------------
# 3) 샘플 Intent 리스트
# -----------------------------
INTENTS = [
    "allow tcp from A to B",
    "block icmp",
    "limit bandwidth 10Mbps for hostA",
    "assign qos high to vlan 10",
    "ensure connectivity between hostA and hostB",
    "create vlan 20 name Engineering",
    "delete vlan 10",
    "set route 10.0.0.0/24 via 192.168.1.1",
    "monitor latency between hostA and hostB",
    "backup configuration now",
]


# -----------------------------
# 4) 표 출력 / CLI
# -----------------------------
def print_table(models, intents):
    header = [
        "No.",
        "IntentLang",
        "JSON Semantic Model",
        "P4/OpenFlow",
        "Cisco Config",
        "Linux Config",
    ]
    print("\t".join(header))

    for i, (intent, model) in enumerate(zip(intents, models), start=1):
        json_str = json.dumps(model)
        p4 = json_to_p4(model)
        cisco = json_to_cisco(model).replace("\n", "\\n")
        linux = json_to_linux(model)
        row = [str(i), intent, json_str, p4, cisco, linux]
        print("\t".join(row))


def main():
    ap = argparse.ArgumentParser(
        description="IntentLang compiler: Intent → JSON → P4/Cisco/Linux"
    )
    ap.add_argument(
        "file",
        nargs="?",
        help="IntentLang 프로그램 파일 (없으면 기본 샘플 사용)",
    )
    args = ap.parse_args()

    if args.file:
        code = Path(args.file).read_text(encoding="utf-8")
        intents = [line.strip() for line in code.splitlines() if line.strip()]
    else:
        code = "\n".join(INTENTS)
        intents = INTENTS

    models = compile_intent(code)
    print_table(models, intents)


if __name__ == "__main__":
    main()
