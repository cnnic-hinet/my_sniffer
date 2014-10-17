#include "select_nif_dlg.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGridLayout>
#include <QLabel>
select_nif_dlg::select_nif_dlg(QWidget *parent) :
    QDialog(parent), selected(0)
{

    //this->nif_list_view = new QListView;
    this->nif_combo_view = new QComboBox;
    this->filter_list_view = new QListView;
    //this->cb_promisc = new QCheckBox(tr("promisc mode"));
    this->btnbox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    this->btnok = btnbox->button(QDialogButtonBox::Ok);
    this->btncancle = btnbox->button(QDialogButtonBox::Cancel);
    this->model_nif = new QStandardItemModel;
    this->model_filter = new QStandardItemModel;
    QGridLayout *gridLayout = new QGridLayout;
    gridLayout->setColumnStretch(0, 1);
    gridLayout->setColumnStretch(1, 3);
    QLabel *label_nic= new QLabel(tr("选择网卡:"));
    QLabel *label_filter = new QLabel(tr("过滤条件:"));
    gridLayout->addWidget(label_nic,0,0);
    gridLayout->addWidget(nif_combo_view,0,1);
    gridLayout->addWidget(label_filter,1,0);
    gridLayout->addWidget(filter_list_view,1,1);
    QVBoxLayout *vl = new QVBoxLayout(this);
    vl->addLayout(gridLayout);
    //vl->addWidget(nif_list_view);
    //vl->addWidget(cb_promisc);
    vl->addWidget(btnbox);
    //初始化
    btnok->setEnabled(false);
    this->setup_nif_info();
    this->setup_filter_info();
    this->setWindowTitle(tr("设置"));

    connect(btnbox, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(btnbox, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(nif_combo_view,SIGNAL(currentIndexChanged(int)), this, SLOT(set_choose(int)));
    //connect(filter_list_view,SIGNAL(model_filter->itemChanged(QStandardItem *)),this,SLOT(set_choose_filter(QStandardItem*)));
    //这里还有些问题，需要有个信号函数
    connect(model_filter,&QStandardItemModel::itemChanged,this,&select_nif_dlg::set_choose_filter);
}
//网卡combo初始化
void select_nif_dlg::setup_nif_info()
{
    all_nif = Tins::NetworkInterface::all();
    for (auto &i : all_nif) {
        QStandardItem *item = new QStandardItem(i.name().c_str());
        //item->setFlags(Qt::ItemIsEnabled|Qt::ItemIsSelectable|Qt::ItemIsUserCheckable);
        //item->setCheckState(Qt::Unchecked);
        model_nif->appendRow(item);
    }
    //this->nif_list_view->setModel(model);
    this->nif_combo_view->setModel(model_nif);
}
//初始化filter_list信息
void select_nif_dlg::setup_filter_info()
{
    all_filter.push_back("all");
    all_filter.push_back("arp");
    all_filter.push_back("tcp");
    all_filter.push_back("udp");
    //all_filter.push_back("http");
    //all_filter.push_back("dns");
    for(auto &i : all_filter)
    {
        QStandardItem *item = new QStandardItem(i);
        item->setFlags(Qt::ItemIsEnabled|Qt::ItemIsSelectable|Qt::ItemIsUserCheckable);
        item->setCheckState(Qt::Unchecked);
        model_filter->appendRow(item);
    }
    this->filter_list_view->setModel(model_filter);
}
//filter信息初始化

void select_nif_dlg::set_choose(int)
{
    selected = this->nif_combo_view->currentIndex();
}

//以下是使用list的时候的情况
//void select_nif_dlg::set_choose(QStandardItem *item)
//{
//    QStandardItem *tmpitem;
//    btnok->setEnabled(false);
//    if (item->checkState() == Qt::Checked) {
//        for (int i = 0; i < model->rowCount(); i++) {
//            tmpitem = model->item(i, 0);
//            if (tmpitem != item)
//                tmpitem->setCheckState(Qt::Unchecked);
//            else
//                selected = i;
//        }
//        btnok->setEnabled(true);
//    }
//}

Tins::NetworkInterface select_nif_dlg::get_selected()
{
    return all_nif[selected];
}


bool select_nif_dlg::use_promisc()
{
    return true;
}

void select_nif_dlg::set_choose_filter(QStandardItem *item)
{
    QStandardItem *tempitem;
    btnok->setEnabled(false);
    if(item->checkState()==Qt::Checked){
        for(int i = 0;i<model_filter->rowCount();i++)
        {
            tempitem = model_filter->item(i,0);
            if(tempitem != item)
                tempitem->setCheckState(Qt::Unchecked);
            else
                selected_filter = i;
        }
        btnok->setEnabled(true);
    }
}
QString select_nif_dlg::get_select_filter()
{
    return all_filter[selected_filter];
}
