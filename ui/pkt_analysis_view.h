#ifndef PKT_ANALYSIS_VIEW_H
#define PKT_ANALYSIS_VIEW_H
#include <QMainWindow>
#include <ui/pkt_tree_view.h>
#include <QTextEdit>
#include <vector>
#include <QLabel>
class pkt_analysis_view : public QMainWindow
{
        Q_OBJECT
    public:
        pkt_analysis_view(QWidget *parent=0);
        pkt_tree_view *tv;
        QTextEdit *edit;
        QLabel *label;
        void show_data(std::vector<uint8_t> &data);

};

#endif // PKT_ANALYSIS_VIEW_H
