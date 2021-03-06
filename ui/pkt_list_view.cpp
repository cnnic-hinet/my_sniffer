#include "pkt_list_view.h"
pkt_list_view::pkt_list_view(QWidget *parent) :
    QTreeView(parent), item_cnt(0)
{
    model = new QStandardItemModel;
    set_header();
    this->setModel(model);
}

void pkt_list_view::set_header()
{
    model->setColumnCount(6);
    model->setHeaderData(0, Qt::Horizontal, tr("序号"));
    model->setHeaderData(1, Qt::Horizontal, tr("时间"));
    model->setHeaderData(2, Qt::Horizontal, tr("来源地址"));
    model->setHeaderData(3, Qt::Horizontal, tr("目标地址"));
    model->setHeaderData(4, Qt::Horizontal, tr("协议"));
    model->setHeaderData(5, Qt::Horizontal, tr("概要信息"));
}

void pkt_list_view::append_item(const char *timestr, const char *srcaddr, const char *dstaddr,
                                const char *prot/*, uint32_t size*/,QString simple_info)
{
    static QStandardItem *item;

    item = new QStandardItem(QString::number(item_cnt));
    model->setItem(item_cnt, 0, item);
    item = new QStandardItem(timestr);
    model->setItem(item_cnt, 1, item);
    item = new QStandardItem(srcaddr);
    model->setItem(item_cnt, 2, item);
    item = new QStandardItem(dstaddr);
    model->setItem(item_cnt, 3, item);
    item = new QStandardItem(prot);
    model->setItem(item_cnt, 4, item);
//    item = new QStandardItem(QString::number(size));
//    model->setItem(item_cnt, 5, item);
    item = new QStandardItem(simple_info);
    model->setItem(item_cnt,5,item);
    item_cnt++;
}

int pkt_list_view::get_item_number(QModelIndex &index)
{
    return model->data(index,0).toString().toInt();
}

void pkt_list_view::clear()
{
    model->clear();
    item_cnt = 0;
    set_header();
}
