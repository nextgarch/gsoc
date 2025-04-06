// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define KEY_SIZE 32
#define NUM_REGISTERS 1024
const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TCP_PROTOCOL = 6;
const bit<8> UDP_PROTOCOL = 17;
const bit<8> TCP_FIN = 1; 


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

struct metadata {
    bit<32> pkt_count;
    bit<32> byte_count;
    bit<32> avg_pkt_size;
    bit<32> duration;
    bit<32> avg_iat;

    bit<32> src_addr;
    bit<32> dst_addr;
    bit<16> src_port;
    bit<16> dst_port;
    bit<8> protocol;

    bit<32> flow_index;
    bit<32> last_seen;
    bit<32> first_seen;
    bit<32> curr_time;
    bit<32> inter_arrival;
    bit<32> total_iat;
    
    
    
    bit<8>  result;
    bit<1> send_digest;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t        udp;
}

struct digest_t{
    bit<32> src_addr;
    bit<32> dst_addr;
    bit<16> src_port;
    bit<16> dst_port;
    bit<8> protocol;
    bit<8> result;
    bit<32> byte_count;
    bit<32> avg_iat;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.src_addr=hdr.ipv4.srcAddr;
        meta.dst_addr=hdr.ipv4.dstAddr;
        meta.protocol=hdr.ipv4.protocol;

        transition select(hdr.ipv4.protocol) {
            TCP_PROTOCOL: parse_tcp;
            UDP_PROTOCOL: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        meta.src_port=hdr.tcp.srcPort;
        meta.dst_port=hdr.tcp.dstPort;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        meta.src_port=hdr.udp.srcPort;
        meta.dst_port=hdr.udp.dstPort;
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // Sample register definition
    register<bit<32>>(NUM_REGISTERS) r_pkt_count;
    register<bit<32>>(NUM_REGISTERS) r_byte_count;
    register<bit<32>>(NUM_REGISTERS) r_first_seen;
    register<bit<32>>(NUM_REGISTERS) r_last_seen;
    register<bit<32>>(NUM_REGISTERS) r_total_iat;
    
    // TODO: Populate the other registers here

    //playing with tuples and hasssshh

    action compute_flow_index(){
        hash(meta.flow_index,
        HashAlgorithm.crc32,
        (bit<16>)0,
        {meta.src_addr,meta.dst_addr,meta.src_port,meta.dst_port,meta.protocol},
        (bit<32>)NUM_REGISTERS);
    }

//     action update_flow_stats(){

//         meta.curr_time=(bit<32>)standard_metadata.ingress_global_timestamp;

//         r_pkt_count.read(meta.pkt_count, meta.flow_index);
//         r_byte_count.read(meta.byte_count, meta.flow_index);
//         r_first_seen.read(meta.first_seen, meta.flow_index);
//         r_last_seen.read(meta.last_seen, meta.flow_index);
//         r_total_iat.read(meta.total_iat, meta.flow_index);

//         if (meta.pkt_count == 0) {
//             meta.first_seen = meta.curr_time;
//             meta.last_seen = meta.curr_time;
//             meta.pkt_count = 1;
//             meta.byte_count = (bit<32>)standard_metadata.packet_length;
//             meta.avg_pkt_size = (bit<32>)standard_metadata.packet_length;
//             meta.total_iat = 0;
//             meta.avg_iat = 0;
//             meta.duration = 0;
//         } else {//damn i like this one
         
//         meta.inter_arrival = meta.curr_time - meta.last_seen;
            
          
//         meta.pkt_count = meta.pkt_count + 1;
//         meta.byte_count = meta.byte_count + (bit<32>)standard_metadata.packet_length;
            
//             // Update avg_pkt_size = byte_count / pkt_count
//         meta.avg_pkt_size = (meta.avg_pkt_size*7+(bit<32>)standard_metadata.packet_length)>>3;
     
//             // Update duration = current_time - first_seen
//         meta.duration = meta.curr_time - meta.first_seen;
            
//             // Update total inter-arrival time
//         meta.total_iat = meta.total_iat + meta.inter_arrival;
            
//             // Calculate avg_iat = total_iat / (pkt_count - 1)
//         if (meta.pkt_count > 1) {
//             meta.avg_iat = meta.total_iat / (meta.pkt_count - 1);
//             }
            
//             // Update last seen timestamp
//         meta.last_seen = meta.curr_time;
//         }

//         //final updationnnn


//         r_pkt_count.write(meta.flow_index, meta.pkt_count);
//         r_byte_count.write(meta.flow_index, meta.byte_count);
//         r_first_seen.write(meta.flow_index, meta.first_seen);
//         r_last_seen.write(meta.flow_index, meta.last_seen);
//         r_total_iat.write(meta.flow_index, meta.total_iat);



//     }



//     action write_result(bit<8> result) {
//         meta.result = result;
//     }

//     table classifier {
//         key = {
            
//             meta.byte_count: exact;
//             meta.avg_iat: exact;
//             meta.pkt_count: exact;
//             meta.avg_pkt_size: exact;
//             meta.duration: exact;
            
//             // hdr.tcp.flags: exact;
//         }
//         actions = {
//             write_result;
//             NoAction;
//         }
//         size = 1024;
//         default_action = NoAction();
//     }

//     action forward(egressSpec_t port){
//         standard_metadata.egress_spec=port;
//     }

//     table ipv4_forwarding{
//         key={
//             hdr.ipv4.dstAddr:lpm;
//         }
//         actions={
//             forward;
//             NoAction;
//         }
//         size=1024;
//         default_action=NoAction();
//     }


//     apply {
//         if(!hdr.ipv4.isValid()) return;

//         compute_flow_index();

//         update_flow_stats();       


//         // Apply the classifier
//         classifier.apply();
//         meta.send_digest=0;



//         if(hdr.tcp.isValid() && (hdr.tcp.flags & TCP_FIN)==TCP_FIN){
//             meta.send_digest=1;
//         }
//         if(meta.send_digest==1){
//             digest<digest_t>(1,{
//                 meta.src_addr,
//                 meta.dst_addr,
//                 meta.src_port,
//                 meta.dst_port,
//                 meta.protocol,
//                 meta.result,
//                 meta.byte_count,
//                 meta.avg_iat
//             });
//         }
//         ipv4_forwarding.apply();
//     }
// }
action update_flow_stats(){
        // Using 48-bit timestamp now
        // meta.curr_time = standard_metadata.ingress_global_timestamp;
        meta.curr_time = (bit<32>)(standard_metadata.ingress_global_timestamp & 0xFFFFFFFF);
        r_pkt_count.read(meta.pkt_count, meta.flow_index);
        r_byte_count.read(meta.byte_count, meta.flow_index);
        r_first_seen.read(meta.first_seen, meta.flow_index);
        r_last_seen.read(meta.last_seen, meta.flow_index);
        r_total_iat.read(meta.total_iat, meta.flow_index);

        if (meta.pkt_count == 0) {
            meta.first_seen = (bit<32>)(meta.curr_time & 0xFFFFFFFF); // Truncate to 32 bits
            meta.last_seen = (bit<32>)(meta.curr_time & 0xFFFFFFFF);  // Truncate to 32 bits
            meta.pkt_count = 1;
            meta.byte_count = (bit<32>)standard_metadata.packet_length;
            meta.avg_pkt_size = (bit<32>)standard_metadata.packet_length; // First packet, size = average
            meta.total_iat = 0;
            meta.avg_iat = 0;
            meta.duration = 0;
        } else {
            // Calculate inter-arrival time (truncate to 32 bits if needed)
            meta.inter_arrival = (bit<32>)((meta.curr_time & 0xFFFFFFFF) - meta.last_seen);
            
            meta.pkt_count = meta.pkt_count + 1;
            meta.byte_count = meta.byte_count + (bit<32>)standard_metadata.packet_length;
            
            // Estimate avg_pkt_size without division
            // This is an approximation using a weighted average
            // avg = (old_avg * (n-1) + new_pkt) / n becomes:
            // avg = old_avg - (old_avg / n) + (new_pkt / n)
            // We'll simplify further by using (old_avg * 7/8) + (new_pkt * 1/8) to avoid division
            meta.avg_pkt_size = (meta.avg_pkt_size * 7 + (bit<32>)standard_metadata.packet_length) >> 3;
            
            // Update duration = current_time - first_seen
            meta.duration = (bit<32>)((meta.curr_time & 0xFFFFFFFF) - meta.first_seen);
            
            // Update total inter-arrival time
            meta.total_iat = meta.total_iat + meta.inter_arrival;
            
            // Estimate avg_iat without division
            // Similar approach as above
            if (meta.pkt_count > 1) {
                // Moving average approximation
                meta.avg_iat = (meta.avg_iat * 7 + meta.inter_arrival) >> 3;
            }
            
            // Update last seen timestamp
            meta.last_seen = (bit<32>)(meta.curr_time & 0xFFFFFFFF);  // Truncate to 32 bits
        }

        //final updationnnn
        r_pkt_count.write(meta.flow_index, meta.pkt_count);
        r_byte_count.write(meta.flow_index, meta.byte_count);
        r_first_seen.write(meta.flow_index, meta.first_seen);
        r_last_seen.write(meta.flow_index, meta.last_seen);
        r_total_iat.write(meta.flow_index, meta.total_iat);
    }

    action write_result(bit<8> result) {
        meta.result = result;
    }

    table classifier {
        key = {
            meta.byte_count: exact;
            meta.avg_iat: exact;
            meta.pkt_count: exact;
            meta.avg_pkt_size: exact;
            meta.duration: exact;
            // hdr.tcp.flags: exact;
        }
        actions = {
            write_result;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action forward(egressSpec_t port){
        standard_metadata.egress_spec = port;
    }

    table ipv4_forwarding{
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if(!hdr.ipv4.isValid()) return;

        compute_flow_index();
        update_flow_stats();       

        // Apply the classifier
        classifier.apply();
        meta.send_digest = 0;

        if(hdr.tcp.isValid() && (hdr.tcp.flags & TCP_FIN) == TCP_FIN){
            meta.send_digest = 1;
        }
        
        if(meta.send_digest == 1){
            digest<digest_t>(1, {
                meta.src_addr,
                meta.dst_addr,
                meta.src_port,
                meta.dst_port,
                meta.protocol,
                meta.result,
                meta.byte_count,
                meta.avg_iat
            });
        }
        
        ipv4_forwarding.apply();
    }
}
/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;