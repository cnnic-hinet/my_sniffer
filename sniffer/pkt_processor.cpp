#include "pkt_processor.h"
#include <ctime>
#include <cstdio>
#include <cstring>
#include <vector>
#include <QDebug>

pkt_processor::pkt_processor(queue_t *pkt_queue, QMutex *stop_mutex) :
    pkt_worker(pkt_queue, stop_mutex), pkt_cnt(0)
{
}
void pkt_deleter(void *pkt)
{
    Tins::Packet *pkt_ = (Tins::Packet *)pkt;
    delete pkt_;
}

void pkt_processor::run()
{
    Tins::Packet *pkt;
    pkt_cnt = 0;
    while (true) {
        stop_mutex->lock();
        if (stop) {
            stop_mutex->unlock();
            break;
        }
        stop_mutex->unlock();
        queue_get_wait(pkt_queue, (void **)&pkt);
        proc_pkt(pkt);
    }
    queue_flush_complete(pkt_queue, pkt_deleter);
}


void pkt_processor::proc_pkt(Tins::Packet *pkt)
{
    static struct pkt_info_t *pkt_info;
    static Tins::PDU         *pdu;
    static Tins::PDU::PDUType pdutype;
    static QString            simple_info;

    static QString            http_info;
    static Tins::Timestamp    tv;
    static const char        *src, *dst, *prot;
    static size_t             size;
    static uint8_t            max_layer;
    static QString            sport;
    static QString            dport;

    pkt_info = new struct pkt_info_t;
    pdu      = pkt->pdu();
    tv       = pkt->timestamp();
    size     = pdu->size();

    pdutype  = pdu->pdu_type();

    //Layer I
    pkt_info->LayerI.Frame.size = size;
    max_layer = 1;
    //Layer II
    if (pdutype == Tins::PDU::PDUType::ETHERNET_II) {
        static Tins::EthernetII *eiipdu;
        eiipdu = (Tins::EthernetII *)pdu;
        pkt_info->LayerIIType = pkt_info_t::layer_ii_type::EthernetII;
        strncpy(pkt_info->LayerII.EthernetII.eii_dst_addr,
                eiipdu->dst_addr().to_string().c_str(),
                31);
        pkt_info->LayerII.EthernetII.eii_dst_addr[31] = '\0';
        strncpy(pkt_info->LayerII.EthernetII.eii_src_addr,
                eiipdu->src_addr().to_string().c_str(),
                31);
        pkt_info->LayerII.EthernetII.eii_src_addr[31] = '\0';
        pkt_info->LayerII.EthernetII.eii_header_size  = eiipdu->header_size();
        pkt_info->LayerII.EthernetII.eii_trailer_size = eiipdu->trailer_size();
        pkt_info->LayerII.EthernetII.eii_type         = eiipdu->payload_type();

        pkt_info->LayerII.EthernetII.eii_data_offset  = 0;
        pkt_info->LayerII.EthernetII.eii_data_len     = pkt_info->LayerII.EthernetII.eii_header_size;

        src = pkt_info->LayerII.EthernetII.eii_src_addr;
        dst = pkt_info->LayerII.EthernetII.eii_dst_addr;
        prot = "EthernetII";

        max_layer = 2;

    } else {
        fprintf(stderr, "pdutype : %d\n", pdutype);
        goto proc_failed;
    }

    pdu = pdu->inner_pdu();
    pdutype = pdu->pdu_type();
    if (pdu == nullptr)
        goto proc_success;
    if (pdutype == Tins::PDU::PDUType::IP)
    {
        static Tins::IP *ippdu;
        ippdu = (Tins::IP*)pdu;
        pkt_info->LayerIIIType = pkt_info_t::layer_iii_type::IP;
        strncpy(pkt_info->LayerIII.IPv4.ip_dst_addr,ippdu->dst_addr().to_string().c_str(),15);
        pkt_info->LayerIII.IPv4.ip_dst_addr[15] = '\0';
        strncpy(pkt_info->LayerIII.IPv4.ip_src_addr,ippdu->src_addr().to_string().c_str(),15);
        pkt_info->LayerIII.IPv4.ip_src_addr[15] = '\0';
        pkt_info->LayerIII.IPv4.ip_version = ippdu->version();
        pkt_info->LayerIII.IPv4.ip_header_size = ippdu->header_size();
        pkt_info->LayerIII.IPv4.ip_tos = ippdu->tos();
        pkt_info->LayerIII.IPv4.ip_total_len = ippdu->size();
        pkt_info->LayerIII.IPv4.ip_id = ippdu->id();

        //some problem
        pkt_info->LayerIII.IPv4.ip_frag_flags = '0';

        pkt_info->LayerIII.IPv4.ip_frag_offset = ippdu->frag_off();
        pkt_info->LayerIII.IPv4.ip_ttl = ippdu->ttl();
        pkt_info->LayerIII.IPv4.ip_protocol = ippdu->protocol();
        pkt_info->LayerIII.IPv4.ip_header_checksum = ippdu->checksum();

        src = pkt_info->LayerIII.IPv4.ip_src_addr;
        dst = pkt_info->LayerIII.IPv4.ip_dst_addr;
        prot = "IPv4";
        max_layer = 3;
        pkt_info->find_string.push_back("IP");
    }
    else if(pdutype == Tins::PDU::PDUType::ARP)
    {
        static Tins::ARP *arppdu;
        arppdu = (Tins::ARP*)pdu;
        pkt_info->LayerIIIType = pkt_info_t::layer_iii_type::ARP;
        //formating
        strncpy(pkt_info->LayerIII.ARP.arp_sender_ip_addr,arppdu->sender_ip_addr().to_string().c_str(),15);
        pkt_info->LayerIII.ARP.arp_sender_ip_addr[15] = '\0';
        strncpy(pkt_info->LayerIII.ARP.arp_sender_hw_addr,arppdu->sender_hw_addr().to_string().c_str(),31);
        pkt_info->LayerIII.ARP.arp_sender_hw_addr[31] = '\0';
        strncpy(pkt_info->LayerIII.ARP.arp_target_ip_addr,arppdu->target_ip_addr().to_string().c_str(),15);
        pkt_info->LayerIII.ARP.arp_target_ip_addr[15] = '\0';
        strncpy(pkt_info->LayerIII.ARP.arp_target_hw_addr,arppdu->target_hw_addr().to_string().c_str(),31);
        pkt_info->LayerIII.ARP.arp_target_hw_addr[31] = '\0';
        pkt_info->LayerIII.ARP.arp_hw_type = arppdu->hw_addr_format();
        pkt_info->LayerIII.ARP.arp_prot_type = arppdu->prot_addr_format();
        pkt_info->LayerIII.ARP.arp_hw_len = arppdu->hw_addr_length();
        pkt_info->LayerIII.ARP.arp_prot_len = arppdu->prot_addr_length();
        pkt_info->LayerIII.ARP.arp_opcode = arppdu->opcode();
        //some problem
        pkt_info->LayerIII.ARP.arp_data_offset = 0;
        pkt_info->LayerIII.ARP.arp_data_len = 0;
        //display the layerII's information witch has been stroed
        src = pkt_info->LayerII.EthernetII.eii_src_addr;
        dst = pkt_info->LayerII.EthernetII.eii_dst_addr;
        simple_info = "Who is " + (QString)pkt_info->LayerIII.ARP.arp_target_ip_addr + " , please tell " + (QString)pkt_info->LayerIII.ARP.arp_sender_ip_addr;
        prot = "ARP";
        max_layer = 3;
        pkt_info->find_string.push_back("ARP");
    }
    else {
//        fprintf(stderr, "pdutype : %d\n", pdutype);
        goto proc_failed;
    }

    if(pdutype == Tins::PDU::PDUType::IP)
    {
        pdu = pdu->inner_pdu();
        pdutype = pdu->pdu_type();
        if(pdu == nullptr)
            goto proc_success;
        if(pdutype == Tins::PDU::PDUType::TCP)
        {
            static Tins::TCP *tcppdu;
            tcppdu = (Tins::TCP*)pdu;
            pkt_info->LayerIVType = pkt_info_t::layer_iv_type::TCP;

            //data range
            pkt_info->LayerIV.TCP.tcp_data_len = tcppdu->size();
            pkt_info->LayerIV.TCP.tcp_data_offset = tcppdu->data_offset();
            //protocol format
            pkt_info->LayerIV.TCP.tcp_sport = tcppdu->sport();
            pkt_info->LayerIV.TCP.tcp_dport = tcppdu->dport();
            pkt_info->LayerIV.TCP.tcp_ack_seq = tcppdu->ack_seq();
            pkt_info->LayerIV.TCP.tcp_checksum = tcppdu->checksum();
            pkt_info->LayerIV.TCP.tcp_flags_syn = tcppdu->SYN;
            pkt_info->LayerIV.TCP.tcp_flags_fin = tcppdu->FIN;
            pkt_info->LayerIV.TCP.tcp_flags_ack = tcppdu->ACK;
            pkt_info->LayerIV.TCP.tcp_seq = tcppdu->seq();
            /*to be continued*/
            //display
            //TCP 概要信息
            if(pkt_info->LayerIV.TCP.tcp_ack_seq ==0)
            {
                simple_info = "This is syn , and syn_seq =" + QString::fromStdString(std::to_string(pkt_info->LayerIV.TCP.tcp_seq));
            }
            if(pkt_info->LayerIV.TCP.tcp_ack_seq !=0)
            {
                simple_info="sys seq ="+QString::fromStdString(std::to_string(pkt_info->LayerIV.TCP.tcp_seq)) +\
                        "and ack_seq =" + QString::fromStdString(std::to_string(pkt_info->LayerIV.TCP.tcp_ack_seq));
            }

            //各种赋值
            src = pkt_info->LayerIII.IPv4.ip_src_addr;
            dst = pkt_info->LayerIII.IPv4.ip_dst_addr;
            prot = "TCP";
            max_layer = 4;
            pkt_info->find_string.push_back("TCP");
            //char转QString
            sport = (QString::fromStdString(std::to_string(pkt_info->LayerIV.TCP.tcp_sport)));
            dport = (QString::fromStdString(std::to_string(pkt_info->LayerIV.TCP.tcp_dport)));

        }
        else if(pdutype == Tins::PDU::PDUType::UDP)
        {
            static Tins::UDP *udppdu;
            udppdu = (Tins::UDP*)pdu;
            pkt_info->LayerIVType = pkt_info_t::layer_iv_type::UDP;

            pkt_info->LayerIV.UDP.udp_checksum = udppdu->checksum();
            pkt_info->LayerIV.UDP.udp_len = udppdu->length();
            pkt_info->LayerIV.UDP.udp_sport = udppdu->sport();
            pkt_info->LayerIV.UDP.udp_dport = udppdu->dport();

            src = pkt_info->LayerIII.IPv4.ip_src_addr;
            dst = pkt_info->LayerIII.IPv4.ip_dst_addr;
            //UDP显示概要
            //总结：由char数组转为QString直接强制转换即可
            //但是从Int转为QString，需要QString::fromStdString(std::to_string(xxx))
            simple_info =QString(pkt_info->LayerIII.IPv4.ip_src_addr) + ":" + \
                QString::fromStdString(std::to_string(pkt_info->LayerIV.UDP.udp_sport)) + \
                    " -> " + QString(pkt_info->LayerIII.IPv4.ip_dst_addr) +\
                    ":" + QString::fromStdString(std::to_string(pkt_info->LayerIV.UDP.udp_dport));
            prot = "UDP";
            max_layer = 4;
            pkt_info->find_string.push_back("UDP");
            sport = (QString::fromStdString(std::to_string(pkt_info->LayerIV.UDP.udp_sport)));
            dport = (QString::fromStdString(std::to_string(pkt_info->LayerIV.UDP.udp_dport)));
        }
        else {
//            fprintf(stderr, "pdutype : %d\n", pdutype);
            goto proc_failed;
        }
    }

    if(pdutype == Tins::PDU::PDUType::UDP)
    {
        if(pkt_info->LayerIV.UDP.udp_dport == 53)
        {
            Tins::DNS dns = pdu->rfind_pdu<Tins::RawPDU>().to<Tins::DNS>();
            for(auto &query : dns.queries())
            {
                http_info = QString::fromStdString(query.dname());
                simple_info = "Want to query :" + QString::fromStdString(query.dname());
            }
            max_layer = 7;
            prot ="DNS";
            pkt_info->find_string.push_back("DNS");
        }
    }
    if(pdutype == Tins::PDU::PDUType::TCP)
    {
        if(pkt_info->LayerIV.TCP.tcp_dport == 80)
        {
            simple_info = http_info;
            //simple_info = "Reading webpage:" + http_info;
            max_layer = 7;
            prot = "HTTP";
            pkt_info->find_string.push_back("HTTP");
        }
    }



proc_success:
    PKT_INFO_SET_TIMESTR(pkt_info, __timestamp_to_str(tv));
    PKT_INFO_SET_SRC(pkt_info, src);
    PKT_INFO_SET_DST(pkt_info, dst);
    PKT_INFO_SET_PROTOCOL(pkt_info, prot);
    PKT_INFO_SET_SIZE(pkt_info, size);
    PKT_INFO_SET_MAX_LAYER(pkt_info, max_layer);
    PKT_INFO_SET_DATA(pkt_info, pkt->pdu()->serialize());
    pkt_info->simple_info = simple_info;
    //pkt_info->find_string = find_string;
    pkt_info->sport = sport;
    pkt_info->dport = dport;
    emit new_pkt(pkt_info);
    return;
proc_failed:
    delete pkt_info;
    return;


}

const char *pkt_processor::__timestamp_to_str(Tins::Timestamp &timestamp)
{
    time_t sec_tv = timestamp.seconds();
    struct tm *localtm = std::localtime(&sec_tv);
    static char tmpstr[64];
    memset(tmpstr, 0x0, sizeof(tmpstr));
    std::strftime(tmpstr, 31, "%F %T", localtm);
    std::snprintf(tmpstr + strlen(tmpstr), 31, " %lu ms %lu us",
                  (unsigned long)timestamp.microseconds() / 1000,
                  (unsigned long)timestamp.microseconds() % 1000);
    return tmpstr+11;
}
