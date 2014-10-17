#include <QtWidgets>
#include "pieview.h"
#include "pkt_count.h"
#include <QString>
pkt_count::pkt_count()
{

    setupModel();
    setupViews();

    statusBar();

    setWindowTitle(tr("统计图"));
    resize(870, 550);
}

void pkt_count::setupModel()
{
    model_count = new QStandardItemModel(8, 2, this);
    model_count->setHeaderData(0, Qt::Horizontal, tr("协议"));
    model_count->setHeaderData(1, Qt::Horizontal, tr("数目"));
}

void pkt_count::setupViews()
{
    QSplitter *splitter = new QSplitter;
    QTableView *table = new QTableView;
    pieChart = new PieView;
    splitter->addWidget(table);
    splitter->addWidget(pieChart);
    splitter->setStretchFactor(0, 0);
    splitter->setStretchFactor(1, 1);

    table->setModel(model_count);
    pieChart->setModel(model_count);

    QItemSelectionModel *selectionModel = new QItemSelectionModel(model_count);
    table->setSelectionModel(selectionModel);
    pieChart->setSelectionModel(selectionModel);

    QHeaderView *headerView = table->horizontalHeader();
    headerView->setStretchLastSection(true);

    setCentralWidget(splitter);
}

void pkt_count::setupData(int tcp, int udp, int arp, int total)
{
    QString str;
    if(arp != 0)
    {
        str = "ARP," + QString::number(arp) + ",#8d5a93;";

    }
    if(udp != 0)
    {
        str += "UDP," + QString::number(udp) + ",#ae4d66;";
    }
    if(tcp != 0)
    {
        str += "TCP," + QString::number(tcp) + ",#8080b3;";
    }
    (void)(total);
    QStringList pieces = str.split(";",QString::SkipEmptyParts);
    QStringList sub_piece;
    model_count->removeRows(0, model_count->rowCount(QModelIndex()), QModelIndex());
    for(int i=0;i<pieces.size();i++)
    {
        sub_piece = pieces[i].split(",",QString::SkipEmptyParts);
        model_count->insertRows(i,1,QModelIndex());
        model_count->setData(model_count->index(i,0,QModelIndex()),sub_piece.value(0));
        model_count->setData(model_count->index(i,1,QModelIndex()),sub_piece.value(1));
        model_count->setData(model_count->index(i,0,QModelIndex()),QColor(sub_piece.value(2)),Qt::DecorationRole);

    }
}
