# #!/usr/bin/env python3

# import argparse
# import json
# import contextlib
# import p4runtime_sh.shell as p4sh

# CFG_DIR = "cfg"
# BRIDGE_ID = 1

# # Fields expected in the rules
# MATCH_FIELDS = [
#                 "pkt_count", 
#                 "byte_count", 
#                 "avg_pkt_size", 
#                 "duration", 
#                 "avg_iat"
#                 ]


# # Float fields that need to be scaled to int for exact match
# FLOAT_SCALES = {
#     "avg_iat": 1000,    # 0.005 → 5
#     "duration": 1000    # 0.02 → 20
# }

# if __name__ == '__main__':
#     parser = argparse.ArgumentParser(description='Decision Tree Controller')
#     parser.add_argument('--grpc-port', required=True, help='GRPC Port (e.g., 50001)')
#     parser.add_argument('--topo-config', required=True, help='Path to topology config (e.g., topo/2.json)')
#     args = parser.parse_args()

#     grpc_port = args.grpc_port
#     switch_name = f"decision_tree-{grpc_port}"

#     # Load decision tree rules from topo
#     with open(args.topo_config, 'r') as f:
#         topo = json.load(f)

#     rules = topo.get("decision_tree_rules", {}).get(grpc_port, [])
#     if not rules:
#         print(f"[!] No decision tree rules found in topo config for port {grpc_port}")
#         exit(1)

#     # Setup P4Runtime shell
#     p4sh.setup(
#         device_id=BRIDGE_ID,
#         grpc_addr=f"127.0.0.1:{grpc_port}",
#         election_id=(0, 1),
#         config=p4sh.FwdPipeConfig(
#             f"{CFG_DIR}/{switch_name}-p4info.txt",
#             f"{CFG_DIR}/{switch_name}.json"
#         )
#     )

#     print(f"[✓] Connected to {switch_name} (gRPC {grpc_port})")
#     print(f"[+] Installing {len(rules)} decision tree rules...\n")

#     for rule in rules:
#         try:
#             table_entry = p4sh.TableEntry("MyIngress.classifier")(action="MyIngress.write_result")
            
#             rule_with_defaults={
#                 "pkt_count":0,
#                 "byte_count":0,
#                 "avg_pkt_size":0,
#                 "duration":0,
#                 "avg_iat":0.0
#             }
#             rule_with_defaults.update(rule)

#             for field in MATCH_FIELDS:
#                 # print(f"Field: {field}")
#                 val = rule_with_defaults[field]
#                 if field in FLOAT_SCALES:
                    
#                     val = int(val * FLOAT_SCALES[field])
                    
#                     print(f"  Field {field}: {rule_with_defaults[field]} → scaled to {val}")
#                 else:
#                     print(f"  Field {field}: {val}")
                    
                    
#                 table_entry.match[f"meta.{field}"] = str(val)


#             # table_entry.match["hdr.tcp.flags"] = "0x01"  # Match on FIN
#             table_entry.action["result"] = str(rule["result"])
#             table_entry.insert()
            
#             provided_fields=[f"{k}={rule[k]}"for k in MATCH_FIELDS if k in rule]
#             cond = " AND ".join(provided_fields) if provided_fields else "default"
#             print(f"[✓] Rule installed: if {cond} → result = {rule['result']}")

#         except Exception as e:
#             print(f"[✗] Failed to insert rule {rule}: {e}\n")

#     print("\n[✓] Controller running. Press Ctrl+C to exit.")
#     try:
#         while True:
#             pass
#     except KeyboardInterrupt:
#         print("\n[!] Controller shutting down.")
#         p4sh.teardown()


#!/usr/bin/env python3


#attempt2

# import argparse
# import json
# import contextlib
# import p4runtime_sh.shell as p4sh

# from p4.v1 import p4runtime_pb2
# from p4.config.v1 import p4info_pb2
# import google.protobuf.text_format

# CFG_DIR = "cfg"
# BRIDGE_ID = 1

# MATCH_FIELDS = [
#     "pkt_count",
#     "byte_count",
#     "avg_pkt_size",
#     "duration",
#     "avg_iat"
# ]

# FLOAT_SCALES = {
#     "avg_iat": 1000,
#     "duration": 1000
# }

# def get_digest_id(p4info_path, digest_name):
#     p4info = p4info_pb2.P4Info()
#     with open(p4info_path, 'r') as f:
#         google.protobuf.text_format.Merge(f.read(), p4info)
#     for digest in p4info.digests:
#         if digest.preamble.name == digest_name:
#             return digest.preamble.id
#     raise ValueError(f"Digest '{digest_name}' not found in P4Info")

# def install_digest(digest_id):
#     digest_entry = p4runtime_pb2.DigestEntry()
#     digest_entry.digest_id = digest_id
#     digest_entry.config.max_timeout_ns = 0
#     digest_entry.config.max_list_size = 1
#     digest_entry.config.ack_timeout_ns = 1000000  # 1ms

#     p4sh.client.stream_msg_req_queue.put_nowait(
#         p4runtime_pb2.StreamMessageRequest(digest_entry=digest_entry)
#     )
#     print(f"[✓] Subscribed to digest ID {digest_id}")

# if __name__ == '__main__':
#     parser = argparse.ArgumentParser(description='Decision Tree Controller')
#     parser.add_argument('--grpc-port', required=True, help='GRPC Port (e.g., 50001)')
#     parser.add_argument('--topo-config', required=True, help='Path to topology config (e.g., topo/2.json)')
#     args = parser.parse_args()

#     grpc_port = args.grpc_port
#     switch_name = f"decision_tree-{grpc_port}"
#     p4info_path = f"{CFG_DIR}/{switch_name}-p4info.txt"

#     with open(args.topo_config, 'r') as f:
#         topo = json.load(f)

#     rules = topo.get("decision_tree_rules", {}).get(grpc_port, [])
#     if not rules:
#         print(f"[!] No decision tree rules found in topo config for port {grpc_port}")
#         exit(1)

#     p4sh.setup(
#         device_id=BRIDGE_ID,
#         grpc_addr=f"127.0.0.1:{grpc_port}",
#         election_id=(0, 100),  # Controller = primary
#         config=p4sh.FwdPipeConfig(
#             p4info_path,
#             f"{CFG_DIR}/{switch_name}.json"
#         )
#     )

#     print(f"[✓] Connected to {switch_name} (gRPC {grpc_port})")

#     # 🚨 Install digest subscription
#     try:
#         digest_id = get_digest_id(p4info_path, "digest_t")
#         install_digest(digest_id)
#     except Exception as e:
#         print(f"[✗] Failed to subscribe to digest: {e}")

#     print(f"[+] Installing {len(rules)} decision tree rules...\n")

#     for rule in rules:
#         try:
#             table_entry = p4sh.TableEntry("MyIngress.classifier")(action="MyIngress.write_result")
#             rule_with_defaults = {
#                 "pkt_count": 0,
#                 "byte_count": 0,
#                 "avg_pkt_size": 0,
#                 "duration": 0,
#                 "avg_iat": 0.0
#             }
#             rule_with_defaults.update(rule)

#             for field in MATCH_FIELDS:
#                 val = rule_with_defaults[field]
#                 if field in FLOAT_SCALES:
#                     val = int(val * FLOAT_SCALES[field])
#                     print(f"  Field {field}: {rule_with_defaults[field]} → scaled to {val}")
#                 else:
#                     print(f"  Field {field}: {val}")

#                 table_entry.match[f"meta.{field}"] = str(val)

#             table_entry.action["result"] = str(rule["result"])
#             table_entry.insert()

#             provided_fields = [f"{k}={rule[k]}" for k in MATCH_FIELDS if k in rule]
#             cond = " AND ".join(provided_fields) if provided_fields else "default"
#             print(f"[✓] Rule installed: if {cond} → result = {rule['result']}")

#         except Exception as e:
#             print(f"[✗] Failed to insert rule {rule}: {e}\n")

#     print("\n[✓] Controller running. Press Ctrl+C to exit.")
#     try:
#         while True:
#             pass
#     except KeyboardInterrupt:
#         print("\n[!] Controller shutting down.")
#         p4sh.teardown()

import argparse
import json
import contextlib
import threading

import p4runtime_sh.shell as p4sh
from p4.v1 import p4runtime_pb2
from p4.config.v1 import p4info_pb2
import google.protobuf.text_format

CFG_DIR = "cfg"
BRIDGE_ID = 1

MATCH_FIELDS = [
    "pkt_count",
    "byte_count",
    "avg_pkt_size",
    "duration",
    "avg_iat"
]

FLOAT_SCALES = {
    "avg_iat": 1000,
    "duration": 1000
}

def get_digest_id(p4info_path, digest_name):
    p4info = p4info_pb2.P4Info()
    with open(p4info_path, 'r') as f:
        google.protobuf.text_format.Merge(f.read(), p4info)
    for digest in p4info.digests:
        if digest.preamble.name == digest_name:
            return digest.preamble.id
    raise ValueError(f"Digest '{digest_name}' not found in P4Info")

def install_digest(digest_id):
    digest_entry = p4runtime_pb2.DigestEntry()
    digest_entry.digest_id = digest_id
    digest_entry.config.max_timeout_ns = 0
    digest_entry.config.max_list_size = 1
    digest_entry.config.ack_timeout_ns = 1000000  # 1ms

    p4sh.client.stream_msg_req_queue.put_nowait(
        p4runtime_pb2.StreamMessageRequest(digest_entry=digest_entry)
    )
    print(f"[✓] Subscribed to digest ID {digest_id}")

def handle_digests():
    print("[~] Listening for digest messages...\n")
    while True:
        msg = p4sh.client.stream_msg_resp_queue.get()
        if msg.HasField("digest"):
            digest = msg.digest
            print(f"[📥] Received Digest: {digest}")
            for data in digest.data:
                flow_info = {}
                for member in data.struct.members:
                    flow_info[member.name] = member.bitstring
                print("[✓] Classified Flow:")
                for k, v in flow_info.items():
                    print(f"   {k}: {v}")
                print("-" * 30)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Decision Tree Controller')
    parser.add_argument('--grpc-port', required=True, help='GRPC Port (e.g., 50001)')
    parser.add_argument('--topo-config', required=True, help='Path to topology config (e.g., topo/2.json)')
    args = parser.parse_args()

    grpc_port = args.grpc_port
    switch_name = f"decision_tree-{grpc_port}"
    p4info_path = f"{CFG_DIR}/{switch_name}-p4info.txt"

    with open(args.topo_config, 'r') as f:
        topo = json.load(f)

    rules = topo.get("decision_tree_rules", {}).get(grpc_port, [])
    if not rules:
        print(f"[!] No decision tree rules found in topo config for port {grpc_port}")
        exit(1)

    p4sh.setup(
        device_id=BRIDGE_ID,
        grpc_addr=f"127.0.0.1:{grpc_port}",
        election_id=(0, 100),  # Controller = primary
        config=p4sh.FwdPipeConfig(
            p4info_path,
            f"{CFG_DIR}/{switch_name}.json"
        )
    )

    print(f"[✓] Connected to {switch_name} (gRPC {grpc_port})")

    # Install digest subscription
    try:
        digest_id = get_digest_id(p4info_path, "digest_t")
        install_digest(digest_id)
    except Exception as e:
        print(f"[✗] Failed to subscribe to digest: {e}")

    # Start digest listener in background
    threading.Thread(target=handle_digests, daemon=True).start()

    print(f"[+] Installing {len(rules)} decision tree rules...\n")

    for rule in rules:
        try:
            table_entry = p4sh.TableEntry("MyIngress.classifier")(action="MyIngress.write_result")
            rule_with_defaults = {
                "pkt_count": 0,
                "byte_count": 0,
                "avg_pkt_size": 0,
                "duration": 0,
                "avg_iat": 0.0
            }
            rule_with_defaults.update(rule)

            for field in MATCH_FIELDS:
                val = rule_with_defaults[field]
                if field in FLOAT_SCALES:
                    val = int(val * FLOAT_SCALES[field])
                    print(f"  Field {field}: {rule_with_defaults[field]} → scaled to {val}")
                else:
                    print(f"  Field {field}: {val}")

                table_entry.match[f"meta.{field}"] = str(val)

            table_entry.action["result"] = str(rule["result"])
            table_entry.insert()

            provided_fields = [f"{k}={rule[k]}" for k in MATCH_FIELDS if k in rule]
            cond = " AND ".join(provided_fields) if provided_fields else "default"
            print(f"[✓] Rule installed: if {cond} → result = {rule['result']}\n")

        except Exception as e:
            print(f"[✗] Failed to insert rule {rule}: {e}\n")

    print("[✓] Controller is running. Press Ctrl+C to exit.\n")
    try:
        while True:
            pass  # Keeps the main thread alive while digests are handled in the background
    except KeyboardInterrupt:
        print("\n[!] Controller shutting down.")
        p4sh.teardown()
