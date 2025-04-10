import argparse
import logging
import grpc
import time
import struct
import socket
import random
from datetime import datetime

from p4.v1 import p4runtime_pb2
from p4.v1 import p4runtime_pb2_grpc
from p4.config.v1 import p4info_pb2

import google.protobuf.text_format

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DigestReceiver")

def get_digest_id_from_p4info(p4info_path, digest_name):
    p4info = p4info_pb2.P4Info()
    with open(p4info_path, 'r') as f:
        google.protobuf.text_format.Merge(f.read(), p4info)
    for digest in p4info.digests:
        if digest.preamble.name == digest_name:
            logger.info(f"Found digest ID: {digest.preamble.id} for digest name: {digest_name}")
            return digest.preamble.id
    raise ValueError(f"Digest '{digest_name}' not found in P4Info")

def build_digest_entry(digest_id):
    digest_entry = p4runtime_pb2.DigestEntry()
    digest_entry.digest_id = digest_id
    digest_entry.config.max_timeout_ns = 0
    digest_entry.config.max_list_size = 1
    digest_entry.config.ack_timeout_ns = 1000000  # 1ms
    return digest_entry

def parse_digest(digest_data):
    try:
        src_addr, dst_addr, src_port, dst_port, protocol, result, byte_count, avg_iat = struct.unpack('>IIHHBBII', digest_data)
        src_ip = socket.inet_ntoa(struct.pack('>I', src_addr))
        dst_ip = socket.inet_ntoa(struct.pack('>I', dst_addr))
        return {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'result': result,
            'byte_count': byte_count,
            'avg_iat': avg_iat / 1000.0
        }
    except Exception as e:
        logger.error(f"Error parsing digest data: {e}")
        return None

def handle_digest(digest):
    for digest_data in digest.data:
        for list_item in digest_data.digest.data:
            parsed = parse_digest(list_item.value)
            if parsed:
                logger.info("====== Flow Classification Result ======")
                logger.info(f"5-Tuple: {parsed['src_ip']}:{parsed['src_port']} -> {parsed['dst_ip']}:{parsed['dst_port']} ({parsed['protocol']})")
                logger.info(f"Classification Result: {parsed['result']}")
                logger.info(f"Statistics: {parsed['byte_count']} bytes, Avg IAT: {parsed['avg_iat']:.3f}s")
                logger.info("========================================")
            else:
                logger.warning("Failed to parse digest data")
    return p4runtime_pb2.DigestListAck(digest_id=digest.digest_id, list_id=digest.list_id)

def stream_req_iterator(req):
    yield req
    while True:
        time.sleep(1)  # Keep stream alive

def run_digest_receiver(grpc_addr, device_id, p4info_path, digest_name):
    try:
        digest_id = get_digest_id_from_p4info(p4info_path, digest_name)

        with grpc.insecure_channel(grpc_addr) as channel:
            stub = p4runtime_pb2_grpc.P4RuntimeStub(channel)

            # Just open a stream without trying to become primary
            logger.info(f"[✓] Connected to P4Runtime server at {grpc_addr}")
            stream = stub.StreamChannel(stream_req_iterator(p4runtime_pb2.StreamMessageRequest()))

            # Wait a bit for the stream to establish
            time.sleep(2)

            # Just listen for digest messages without trying to subscribe
            logger.info("[~] Listening for flow classification digests...")

            try:
                for response in stream:
                    if response.HasField("digest"):
                        logger.info("[✓] Received digest message!")
                        ack = handle_digest(response.digest)
                        ack_req = p4runtime_pb2.StreamMessageRequest()
                        ack_req.digest_ack.CopyFrom(ack)
                        stream.write(ack_req)
            except grpc.RpcError as e:
                logger.error(f"[✗] gRPC error: {e}")
    except KeyboardInterrupt:
        logger.info("Shutting down digest receiver")
    except Exception as e:
        logger.error(f"Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='P4Runtime Digest Receiver')
    parser.add_argument('--grpc-addr', required=True, help='P4Runtime gRPC server address (e.g., 127.0.0.1:50001)')
    parser.add_argument('--device-id', type=int, default=1, help='P4Runtime device ID')
    parser.add_argument('--p4info', required=True, help='Path to p4info.pb.txt file')
    parser.add_argument('--digest-name', default='digest_t', help='Name of the digest to listen for')
    args = parser.parse_args()

    run_digest_receiver(args.grpc_addr, args.device_id, args.p4info, args.digest_name)

#safe keeping above code incase of debugging issues

import argparse
import logging
import grpc
import time
import struct
import socket

from p4.v1 import p4runtime_pb2
from p4.v1 import p4runtime_pb2_grpc
from p4.config.v1 import p4info_pb2
import google.protobuf.text_format

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DigestReceiver")


def get_digest_id_from_p4info(p4info_path, digest_name):
    p4info = p4info_pb2.P4Info()
    with open(p4info_path, 'r') as f:
        google.protobuf.text_format.Merge(f.read(), p4info)
    for digest in p4info.digests:
        if digest.preamble.name == digest_name:
            logger.info(f"[✓] Found digest ID: {digest.preamble.id} for '{digest_name}'")
            return digest.preamble.id
    raise ValueError(f"[✗] Digest '{digest_name}' not found in P4Info")


def build_digest_entry(digest_id):
    digest_entry = p4runtime_pb2.DigestEntry()
    digest_entry.digest_id = digest_id
    digest_entry.config.max_timeout_ns = 0
    digest_entry.config.max_list_size = 1
    digest_entry.config.ack_timeout_ns = 1_000_000  # 1 ms
    return digest_entry


def parse_digest(digest_data):
    try:
        src_addr, dst_addr, src_port, dst_port, protocol, result, byte_count, avg_iat = struct.unpack('>IIHHBBII', digest_data)
        src_ip = socket.inet_ntoa(struct.pack('>I', src_addr))
        dst_ip = socket.inet_ntoa(struct.pack('>I', dst_addr))
        return {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'result': result,
            'byte_count': byte_count,
            'avg_iat': avg_iat / 1000.0
        }
    except Exception as e:
        logger.error(f"[✗] Error parsing digest data: {e}")
        return None


def handle_digest(digest):
    for digest_data in digest.data:
        for list_item in digest_data.digest.data:
            parsed = parse_digest(list_item.value)
            if parsed:
                logger.info("\n====== Flow Classification Result ======")
                logger.info(f"5-Tuple: {parsed['src_ip']}:{parsed['src_port']} -> {parsed['dst_ip']}:{parsed['dst_port']} (Protocol: {parsed['protocol']})")
                logger.info(f"Classification Result: {parsed['result']}")
                logger.info(f"Statistics: {parsed['byte_count']} bytes, Avg IAT: {parsed['avg_iat']:.3f} s")
                logger.info("========================================\n")
            else:
                logger.warning("[!] Failed to parse digest item")

    return p4runtime_pb2.DigestListAck(
        digest_id=digest.digest_id,
        list_id=digest.list_id
    )


def stream_req_iterator():
    while True:
        time.sleep(1)


def run_digest_receiver(grpc_addr, device_id, p4info_path, digest_name):
    try:
        digest_id = get_digest_id_from_p4info(p4info_path, digest_name)

        with grpc.insecure_channel(grpc_addr) as channel:
            stub = p4runtime_pb2_grpc.P4RuntimeStub(channel)
            logger.info(f"[✓] Connected to P4Runtime server at {grpc_addr}")

            # Open stream (no arbitration request)
            stream = stub.StreamChannel(stream_req_iterator())

            # Subscribe to digest notifications
            digest_entry = build_digest_entry(digest_id)
            write_req = p4runtime_pb2.WriteRequest()
            write_req.device_id = device_id
            update = write_req.updates.add()
            update.type = p4runtime_pb2.Update.INSERT
            update.entity.digest_entry.CopyFrom(digest_entry)
            stub.Write(write_req)
            logger.info("[+] Subscribed to digest notifications.")

            logger.info("[~] Listening for flow classification digests...\n")
            try:
                for response in stream:
                    if response.HasField("digest"):
                        ack = handle_digest(response.digest)
                        ack_msg = p4runtime_pb2.StreamMessageRequest()
                        ack_msg.digest_ack.CopyFrom(ack)
                        stream.write(ack_msg)
            except grpc.RpcError as e:
                logger.error(f"[✗] gRPC error: {e}")

    except KeyboardInterrupt:
        logger.info("[!] Shutting down digest receiver.")
    except Exception as e:
        logger.error(f"[✗] Error: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='P4Runtime Digest Receiver')
    parser.add_argument('--grpc-addr', required=True, help='P4Runtime gRPC server address (e.g., 127.0.0.1:50001)')
    parser.add_argument('--device-id', type=int, default=1, help='P4Runtime device ID')
    parser.add_argument('--p4info', required=True, help='Path to p4info.pb.txt file')
    parser.add_argument('--digest-name', default='digest_t', help='Name of the digest to listen for')
    args = parser.parse_args()

    run_digest_receiver(args.grpc_addr, args.device_id, args.p4info, args.digest_name)
