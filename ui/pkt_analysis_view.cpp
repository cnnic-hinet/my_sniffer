#include "pkt_analysis_view.h"
#include <QSplitter>
#include <QByteArray>

pkt_analysis_view::pkt_analysis_view(QWidget *parent)
    :QMainWindow(parent)
{
    this->setWindowTitle(tr("分析"));
    this->setFixedSize(400,500);
    QSplitter *splitter = new QSplitter(Qt::Vertical);
    tv = new pkt_tree_view(this);
    edit = new QTextEdit(this);
    label = new QLabel(this);
    label->setText(tr("数据十六进制信息:"));
    splitter->addWidget(tv);
    splitter->addWidget(label);
    splitter->addWidget(edit);
    this->setCentralWidget(splitter);
}

void pkt_analysis_view::show_data(std::vector<uint8_t> &data)
{
    QByteArray *bytearray = new QByteArray;
    for(std::vector<u_int8_t>::iterator iter =data.begin();iter !=data.end();++iter)
    {
        bytearray->append(*iter);
    }
    edit->setText(bytearray->toHex().toUpper());
}
