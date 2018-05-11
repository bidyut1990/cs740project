/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

typedef bit<32> qdepth_t;

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

header tenant_t{
    bit<32> id;
 
   // following 4 fields can be changed in Egress processing
    bit<32> enq_timestamp;  // 32 bit
    bit<32> enq_qdepth;     // 19      typecast
    bit<32> deq_timedelta;   // 32
    bit<32> deq_qdepth;     // 19      typecast
    bit<32> total_pkt_count;
    //
    bit<32> total_packet_length;
    bit<48> inter_packet_gap;        //type


   // bit<32> deq_timedelta;

/*    bit<19> deq_qdepth;
    bit<48> ingress_global_timestamp;
    bit<48> egress_global_timestamp;
*/

}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

struct metadata {
    /* empty */

}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    tenant_t       tenant;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser ParserImpl(packet_in packet,
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
        transition select(hdr.ipv4.protocol){
                 17 : parse_udp;
            default : accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
  //      transition accept;
        transition select(hdr.udp.srcPort){
             default  : parse_tenant;
        //         0    : accept;
        }

    }

    state parse_tenant {
        packet.extract(hdr.tenant);
        transition accept;
    }

}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control verifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop();
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

     /* CHECK AND REMOVE */
    //    hdr.udp.checksum = 0xf0f0;
    //    hdr.tenant.enq_timestamp  =  (qdepth_t)standard_metadata.ingress_global_timestamp ;      
    //    modify_field(int_q_occu, queueing_metadata.enq_qdepth);

    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    register<bit<32>>(256) pkt_count_reg;
    register<bit<32>>(256) pkt_length_reg;
    register<bit<48>>(256) last_seen;
   
    action add_swtrace() { 
             hdr.tenant.enq_timestamp  = standard_metadata.enq_timestamp  ;
             hdr.tenant.enq_qdepth = (qdepth_t)standard_metadata.enq_qdepth ;
             hdr.tenant.deq_timedelta   = standard_metadata.deq_timedelta   ;
             hdr.tenant.deq_qdepth = (qdepth_t)standard_metadata.deq_qdepth ;

	     bit<32> index = hdr.tenant.id;
	     bit<32> temp_var;
             //packet count register code 

             pkt_count_reg.read(temp_var, index);
             temp_var = temp_var + 1;
	     pkt_count_reg.write(index, temp_var);
             hdr.tenant.total_pkt_count = temp_var;

             //packet length register code
             bit<32> current_packet_length;
             current_packet_length = standard_metadata.packet_length;
             pkt_length_reg.read(temp_var, index);
             temp_var = temp_var + current_packet_length;
             pkt_length_reg.write(index, temp_var);
             hdr.tenant.total_packet_length = temp_var;

            //inter packet gap register code   
            bit<48> interval;
            last_seen.read(interval, index);
            interval = standard_metadata.ingress_global_timestamp - interval;
            last_seen.write(index, standard_metadata.ingress_global_timestamp);                     
            hdr.tenant.inter_packet_gap = interval;            
    }

    table swtrace {
        actions = { 
	    add_swtrace; 
	    NoAction; 
        }
        default_action = NoAction();      
    }
    
    apply {
        if (hdr.ipv4.isValid()) {
            swtrace.apply();
        }
    }


}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control computeChecksum(
    inout headers  hdr,
    inout metadata meta)
{
    apply {
        update_checksum(true,
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
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tenant);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
ParserImpl(),
verifyChecksum(),
ingress(),
egress(),
computeChecksum(),
DeparserImpl()
) main;
