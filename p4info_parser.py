from google.protobuf import text_format
from p4.v1 import p4runtime_pb2

class P4InfoParser:
    def __init__(self, p4info_path):
        self.p4info = p4runtime_pb2.P4Info()
        with open(p4info_path, 'r') as f:
            text_format.Merge(f.read(), self.p4info)

    def get_digest_id(self, digest_name):
        for digest in self.p4info.digests:
            if digest.preamble.name == digest_name:
                return digest.preamble.id
        raise ValueError(f"Digest '{digest_name}' not found in P4Info.")
