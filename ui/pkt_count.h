#ifndef PKT_COUNT_H
#define PKT_COUNT_H
#include <QMainWindow>

QT_BEGIN_NAMESPACE
class QAbstractItemModel;
class QAbstractItemView;
class QItemSelectionModel;
QT_END_NAMESPACE

class pkt_count : public QMainWindow
{
    Q_OBJECT

public:
    pkt_count();
public:
    void setupModel();
    void setupViews();
    void setupData(int tcp,int udp,int arp,int total);

    QAbstractItemModel *model_count;
    QAbstractItemView *pieChart;
    QItemSelectionModel *selectionModel;
};
#endif // PKT_COUNT_H
