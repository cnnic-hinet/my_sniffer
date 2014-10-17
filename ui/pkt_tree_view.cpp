#include <QStandardItem>
#include <QString>
#include "pkt_tree_view.h"
#include <QSplitter>
#include <vector>
pkt_tree_view::pkt_tree_view(QWidget *parent) :
    QTreeView(parent)
{
    model = new QStandardItemModel;
    set_header();
    this->setWindowTitle(tr("分析"));
    this->setFixedSize(400,300);
    this->setModel(model);
}

void pkt_tree_view::set_header()
{
    model->setColumnCount(1);
    model->setHeaderData(0, Qt::Horizontal, tr("数据包信息："));
}


void pkt_tree_view::clear()
{
    model->clear();
    set_header();
}
void pkt_tree_view::add_item(pkt_info_t *pi)
{
    QList<QStandardItem *> item;
    item.push_back(new_II_pkt(pi));
    if(pi->max_layer >= 3)
        item.push_back(new_III_pkt(pi));
    if(pi->max_layer >=4)
        item.push_back(new_IV_pkt(pi));
    for(auto &x : item)
    {
        model->appendRow(x);
        setExpanded(model->indexFromItem(x),true);
    }

}

QStandardItem *pkt_tree_view::new_II_pkt(pkt_info_t *pi)
{
    QStandardItem *new_II_item = new QStandardItem;
    QStandardItem *child_item;
    child_item = new QStandardItem;
    new_II_item->setText(QString("Ethernet 包大小： %1 bytes").arg(pi->size));
    child_item->setText(QString("包头大小： %1 bytes").arg(pi->LayerII.EthernetII.eii_header_size));
    new_II_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString("类别 :%1").arg(pi->LayerII.EthernetII.eii_type));
    new_II_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString("源 MAC 地址 :%1").arg(pi->LayerII.EthernetII.eii_src_addr));
    new_II_item->appendRow(child_item);
    child_item = new QStandardItem;
    child_item->setText(QString("目的 MAC 地址 :%1").arg(pi->LayerII.EthernetII.eii_dst_addr));
    new_II_item->appendRow(child_item);
    return new_II_item;
}

QStandardItem *pkt_tree_view::new_III_pkt(pkt_info_t *pi)
{
    if(pi->LayerIIIType == pkt_info_t::layer_iii_type::IP)
    {
        QStandardItem *new_III_item = new QStandardItem;
        QStandardItem *child_item;
        new_III_item->setText(QString("IP 包大小: %1").arg(pi->LayerIII.IPv4.ip_total_len));
        child_item = new QStandardItem;
        child_item->setText(QString("包头大小: %1").arg(pi->LayerIII.IPv4.ip_header_size));
        new_III_item->appendRow(child_item);
        child_item = new QStandardItem;
        child_item->setText(QString("版本 :%1").arg(pi->LayerIII.IPv4.ip_version));
        new_III_item->appendRow(child_item);
        child_item = new QStandardItem;
        child_item->setText(QString("源 IP 地址 :%1").arg(pi->LayerIII.IPv4.ip_src_addr));
        new_III_item->appendRow(child_item);
        child_item = new QStandardItem;
        child_item->setText(QString("目的 IP 地址 :%1").arg(pi->LayerIII.IPv4.ip_dst_addr));
        new_III_item->appendRow(child_item);
        child_item = new QStandardItem;
        child_item->setText(QString("TTL:%1").arg(pi->LayerIII.IPv4.ip_ttl));
        new_III_item->appendRow(child_item);
        child_item = new QStandardItem;
        child_item->setText(QString("协议 :%1").arg(pi->LayerIII.IPv4.ip_protocol));
        new_III_item->appendRow(child_item);
        child_item = new QStandardItem;
        child_item->setText(QString("头校验值 :%1").arg(pi->LayerIII.IPv4.ip_header_checksum));
        new_III_item->appendRow(child_item);
        return new_III_item;
    }
    else
    {
        QStandardItem *new_III_item = new QStandardItem;
        QStandardItem *child_item;
        new_III_item->setText(QString("ARP 头大小: %1").arg(pi->LayerIII.ARP.arp_opcode));
        child_item = new QStandardItem;
        child_item->setText(QString("源 IP 地址 : %1").arg(pi->LayerIII.ARP.arp_sender_ip_addr));
        new_III_item->appendRow(child_item);
        child_item = new QStandardItem;
        child_item->setText(QString("标记 IP 地址 :%1").arg(pi->LayerIII.ARP.arp_target_ip_addr));
        new_III_item->appendRow(child_item);
        child_item = new QStandardItem;
        child_item->setText(QString("源 MAC 地址:%1").arg(pi->LayerIII.ARP.arp_sender_hw_addr));
        new_III_item->appendRow(child_item);
        child_item = new QStandardItem;
        child_item->setText(QString("标记 MAC 地址:%1").arg(pi->LayerIII.ARP.arp_target_hw_addr));
        new_III_item->appendRow(child_item);
        return new_III_item;
    }
}

QStandardItem *pkt_tree_view::new_IV_pkt(pkt_info_t *pi)
{
    if(pi->LayerIVType == pkt_info_t::layer_iv_type::TCP)
    {
        QStandardItem *new_IV_item = new QStandardItem;
        QStandardItem *child_item;
        new_IV_item->setText(QString("TCP 数据大小 :%1").arg(pi->LayerIV.TCP.tcp_data_len));
        child_item = new QStandardItem;
        child_item->setText(QString("TCP 序列号:%1").arg(pi->LayerIV.TCP.tcp_seq));
        new_IV_item->appendRow(child_item);
        child_item = new QStandardItem;
        child_item->setText(QString("源端口 :%1").arg(pi->LayerIV.TCP.tcp_sport));
        new_IV_item->appendRow(child_item);
        child_item = new QStandardItem;
        child_item->setText(QString("目的端口 :%1").arg(pi->LayerIV.TCP.tcp_dport));
        new_IV_item->appendRow(child_item);
        child_item = new QStandardItem;
        child_item->setText(QString("校验值 :%1").arg(pi->LayerIV.TCP.tcp_checksum));
        new_IV_item->appendRow(child_item);
        child_item = new QStandardItem;
        child_item->setText(QString("SYN:%1").arg(pi->LayerIV.TCP.tcp_flags_syn));
        new_IV_item->appendRow(child_item);
        child_item = new QStandardItem;
        child_item->setText(QString("ACK:%1").arg(pi->LayerIV.TCP.tcp_flags_ack));
        new_IV_item->appendRow(child_item);
        child_item = new QStandardItem;
        child_item->setText(QString("FIN:%1").arg(pi->LayerIV.TCP.tcp_flags_fin));
        new_IV_item->appendRow(child_item);
        return new_IV_item;
    }
    else
    {
        QStandardItem *new_IV_item = new QStandardItem;
        QStandardItem *child_item;
        new_IV_item->setText(QString("UDP 数据大小 :%1").arg(pi->LayerIV.UDP.udp_len));
        child_item = new QStandardItem;
        child_item->setText(QString("源端口 :%1").arg(pi->LayerIV.UDP.udp_sport));
        new_IV_item->appendRow(child_item);
        child_item = new QStandardItem;
        child_item->setText(QString("目的端口 :%1").arg(pi->LayerIV.UDP.udp_dport));
        new_IV_item->appendRow(child_item);
        child_item = new QStandardItem;
        child_item->setText(QString("校验值 :%1").arg(pi->LayerIV.UDP.udp_checksum));
        new_IV_item->appendRow(child_item);
        return new_IV_item;
    }
}
