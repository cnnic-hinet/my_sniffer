#ifndef PKT_TREE_VIEW_H
#define PKT_TREE_VIEW_H

#include <QTreeView>
#include <QStandardItemModel>
#include <tins/tins.h>
#include "sniffer/pkt_info.h"

class pkt_tree_view : public QTreeView
{
        Q_OBJECT
    public:
        explicit pkt_tree_view(QWidget *parent = 0);
        void add_item(struct pkt_info_t *pi);
        void clear();
    private:
        void set_header();
        QStandardItem *new_II_pkt(pkt_info_t *pi);
        QStandardItem *new_III_pkt(pkt_info_t *pi);
        QStandardItem *new_IV_pkt(pkt_info_t *pi);
    private:
        QStandardItemModel *model;

};

#endif // PKT_TREE_VIEW_H
