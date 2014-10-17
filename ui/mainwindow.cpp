#include "mainwindow.h"
#include <QHBoxLayout>
#include <QPushButton>
#include <QSplitter>
#include <QMessageBox>
#include <QStatusBar>
#include <QLabel>
#include <QString>
#include <QDebug>
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    smgr = new sniffer_manager;

    lv = new pkt_list_view(this);
//    tv = new pkt_tree_view(0);
    pav = new pkt_analysis_view(this);
    coutv = new pkt_count;
//    QSplitter *splitter = new QSplitter(this);
//    splitter->addWidget(lv);
//    splitter->addWidget(tv);
    pav->hide();
//    setCentralWidget(splitter);
    setCentralWidget(lv);

    create_statusbar();
    create_actions();
    create_toolbars();
    create_menu();
    this->setWindowTitle(tr("嗅探器"));
    this->setFixedSize(850,500);
    connect(smgr->pp_thrd, &pkt_processor::new_pkt, this, &MainWindow::rcv_pkt_info);
    connect(lv->selectionModel(),&QItemSelectionModel::selectionChanged,this,&MainWindow::proc_selected_item);
    connect(button,&QPushButton::clicked,this,&MainWindow::find);
    connect(return_button,&QPushButton::clicked,this,&MainWindow::return_lv);
}

MainWindow::~MainWindow()
{
    smgr->destroy_pkt_info_list();
    delete pav;
    delete smgr;

}

void MainWindow::create_actions()
{
    act_select_nif = new QAction(tr("选择网卡"), this);
    QIcon icon_select(":/sniffer/images/select.png");
    act_select_nif->setIcon(icon_select);
    act_select_nif->setStatusTip(tr("选择一个网卡"));
    connect(act_select_nif, &QAction::triggered, this, &MainWindow::select_nif);

    act_start = new QAction(tr("开始"), this);
    QIcon icon_start(":/sniffer/images/start.png");
    act_start->setIcon(icon_start);
    act_start->setStatusTip(tr("开始捕获"));
    act_start->setEnabled(false);
    connect(act_start, &QAction::triggered, this, &MainWindow::start);

    act_stop = new QAction(tr("结束"), this);
    act_stop->setStatusTip(tr("停止捕获"));
    QIcon icon_stop(":/sniffer/images/stop.png");
    act_stop->setIcon(icon_stop);
    act_stop->setEnabled(false);
    connect(act_stop, &QAction::triggered, this, &MainWindow::stop);

    act_restart = new QAction(tr("重置"),this);
    QIcon icon_restart(":/sniffer/images/repeat.png");
    act_restart->setIcon(icon_restart);
    act_restart->setStatusTip(tr("重新捕获"));
    act_restart->setEnabled(false);
    connect(act_restart,&QAction::triggered,this,&MainWindow::restart);

    act_count = new QAction(tr("统计"),this);
    connect(act_count,&QAction::triggered,this,&MainWindow::count_view);



}

void MainWindow::create_menu()
{
    menu = menuBar()->addMenu(tr("新建"));
    menu->addAction(act_select_nif);
    menu->addAction(act_start);
    menu->addAction(act_stop);
    menu->addAction(act_restart);
    menu = menuBar()->addMenu(tr("统计"));
    menu->addAction(act_count);
}

void MainWindow::create_statusbar()
{
    statusLabel = new QLabel("欢迎使用Sniffer by hi_net");
    statusLabel->setAlignment(Qt::AlignHCenter);
    statusLabel->setMinimumSize(statusLabel->sizeHint());
    this->statusBar()->addWidget(statusLabel);

}

void MainWindow::create_toolbars()
{
    tb_work = addToolBar(tr("capture"));
    //addToolBar(Qt::LeftToolBarArea,tb_work);
    tb_work->setMovable(false);
    //tb_work->addAction(act_select_nif);
    //tb_work->addSeparator();
    tb_work->addAction(act_start);
    tb_work->addAction(act_stop);
    tb_work->addAction(act_restart);
    tb_work->addSeparator();
    //tb_work->addSeparator();
    applay_label = new QLabel(this);
    applay_label->setText(tr("条件查找:"));
    find_box = new QComboBox(this);
    find_box->addItem(tr("协议"));
    find_box->addItem(tr("源IP"));
    find_box->addItem(tr("目的IP"));
    find_box->addItem(tr("源端口"));
    find_box->addItem(tr("目的端口"));
    find_edit = new QLineEdit(this);
    button = new QPushButton(this);
    button->setText(tr("应用"));
    return_button = new QPushButton(this);
    return_button->setText(tr("返回"));
    tb_work->addWidget(applay_label);
    tb_work->addWidget(find_box);
    tb_work->addWidget(find_edit);
    tb_work->addWidget(button);
    tb_work->addWidget(return_button);
}

//SLOTS
void MainWindow::select_nif()
{
    select_nif_dlg sndlg(this);

    if (sndlg.exec() == QDialog::Accepted) {
        //提取已选择的网卡，还有混杂模式的参数
        smgr->set_nif(sndlg.get_selected());
        smgr->set_promisc(sndlg.use_promisc());
        smgr->set_filter(sndlg.get_select_filter());
        //这是提取过滤条件的，还没添加
        //smgr->set_filter();


        if (!smgr->init_sniffer()) {
            QMessageBox::warning(this, tr("Sniffer"),
                                 QString(tr("Cannot init sniffer on ")).append(smgr->get_nif().name().c_str()),
                                 QMessageBox::Ok);
            return;
        }
        act_start->setEnabled(true);
    }
}

void MainWindow::start()
{
    lv->clear();
    smgr->start_capture();
    act_start->setEnabled(false);
    act_stop->setEnabled(true);
}

void MainWindow::stop()
{
    smgr->stop_capture();
    act_stop->setEnabled(false);
    act_start->setEnabled(true);
    act_restart->setEnabled(true);
    //不能毁掉链表，不然在stop后就不能进行包分析了
    //需要设立重新开始按钮
    //smgr->destroy_pkt_info_list();
}

void MainWindow::restart()
{
    smgr->stop_capture();
    act_stop->setEnabled(true);
    act_start->setEnabled(false);
    smgr->destroy_pkt_info_list();
    MainWindow::start();
}

void MainWindow::rcv_pkt_info(pkt_info_t *pkt_info)
{
    lv->append_item(pkt_info->timestr,
                    pkt_info->src,
                    pkt_info->dst,
                    pkt_info->protocol,
                    /*pkt_info->size*/
                    pkt_info->simple_info
                    );
    //将每个包的结构体放入一个list里面
    smgr->pkt_info_list.append(pkt_info);
    //debug 链表的大小
    //fprintf(stderr, "listsize : %d\n", smgr->pkt_info_list.size());
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    pav->close();
    delete pav;
    event->accept();
}
void MainWindow::proc_selected_item(const QItemSelection &selected)
{

    pav->tv->clear();
    pav->show();
    QModelIndexList items = selected.indexes();
    QModelIndex     index = items.first();
    current_pkt_num = lv->get_item_number(index);
    if (current_pkt_num >= 0 && current_pkt_num <= smgr->pkt_info_list.size()) {
        pav->tv->add_item(smgr->pkt_info_list[current_pkt_num]);
        pav->show_data(smgr->pkt_info_list[current_pkt_num]->data);
        //fprintf(stderr, "current_index : %d\n", current_pkt_num);
    }
}

void MainWindow::find()
{
    if(find_box->currentText() =="协议")
        MainWindow::pro_find();
    else if(find_box->currentText() == "源IP" || find_box->currentText() == "目的IP")
        MainWindow::ip_find();
    else if(find_box->currentText() == "源端口" || find_box->currentText() == "目的端口")
        MainWindow::port_find();
}

void MainWindow::pro_find()
{
    QString find_str = find_edit->text().toUpper();
    //qDebug()<<find_str;
    lv->clear();
    for(int i=0;i<smgr->pkt_info_list.size();i++)
    {
        //qDebug()<<smgr->pkt_info_list[i]->find_string;
        if(MainWindow::checkpro(i,find_str))
        {
            lv->append_item(smgr->pkt_info_list[i]->timestr,
                            smgr->pkt_info_list[i]->src,
                            smgr->pkt_info_list[i]->dst,
                            smgr->pkt_info_list[i]->protocol,
                            /*pkt_info->size*/
                            smgr->pkt_info_list[i]->simple_info
                            );
        }
    }
}

void MainWindow::ip_find()
{
    lv->clear();
    if(find_box->currentText() == "源IP")
    {
        for(int i =0;i<smgr->pkt_info_list.size();i++)
        {
            if((QString)smgr->pkt_info_list[i]->LayerIII.IPv4.ip_src_addr == find_edit->text())
            {
                lv->append_item(smgr->pkt_info_list[i]->timestr,
                                smgr->pkt_info_list[i]->src,
                                smgr->pkt_info_list[i]->dst,
                                smgr->pkt_info_list[i]->protocol,
                                /*pkt_info->size*/
                                smgr->pkt_info_list[i]->simple_info
                                );
            }
        }
    }
    else
    {
        for(int i =0;i<smgr->pkt_info_list.size();i++)
        {
            if((QString)smgr->pkt_info_list[i]->LayerIII.IPv4.ip_dst_addr == find_edit->text())
            {
                lv->append_item(smgr->pkt_info_list[i]->timestr,
                                smgr->pkt_info_list[i]->src,
                                smgr->pkt_info_list[i]->dst,
                                smgr->pkt_info_list[i]->protocol,
                                /*pkt_info->size*/
                                smgr->pkt_info_list[i]->simple_info
                                );
            }
        }
    }
}

void MainWindow::port_find()
{
    lv->clear();
    if(find_box->currentText() == "源端口")
    {
        for(int i = 0;i<smgr->pkt_info_list.size();i++)
        {
            qDebug()<<smgr->pkt_info_list[i]->sport<<" : "<<find_edit->text();
            if(smgr->pkt_info_list[i]->sport == find_edit->text())
            {

                lv->append_item(smgr->pkt_info_list[i]->timestr,
                                smgr->pkt_info_list[i]->src,
                                smgr->pkt_info_list[i]->dst,
                                smgr->pkt_info_list[i]->protocol,
                                /*pkt_info->size*/
                                smgr->pkt_info_list[i]->simple_info
                                );
            }
        }
    }
    else
    {
        for(int i = 0;i<smgr->pkt_info_list.size();i++)
        {
            if(smgr->pkt_info_list[i]->dport == find_edit->text())
            {

                lv->append_item(smgr->pkt_info_list[i]->timestr,
                                smgr->pkt_info_list[i]->src,
                                smgr->pkt_info_list[i]->dst,
                                smgr->pkt_info_list[i]->protocol,
                                /*pkt_info->size*/
                                smgr->pkt_info_list[i]->simple_info
                                );

            }
        }
    }
}

bool MainWindow::checkpro(int n,QString &str)
{
    for(int i=0;i<smgr->pkt_info_list[n]->find_string.size();i++)
    {
        if(str == smgr->pkt_info_list[n]->find_string[i])
            return true;
    }
    return false;
}

void MainWindow::return_lv()
{
    lv->clear();
    for(int i = 0;i<smgr->pkt_info_list.size();i++)
    {
        lv->append_item(smgr->pkt_info_list[i]->timestr,
                        smgr->pkt_info_list[i]->src,
                        smgr->pkt_info_list[i]->dst,
                        smgr->pkt_info_list[i]->protocol,
                        /*pkt_info->size*/
                        smgr->pkt_info_list[i]->simple_info
                        );
    }
}

void MainWindow::count_view()
{
    int tcp_count = 0;
    int udp_count = 0;
    int arp_count = 0;
    int total_count = lv->model->rowCount();
    for(int i=0;i<lv->model->rowCount();i++)
    {
        if(lv->model->item(i,4)->text() == "TCP")
            tcp_count ++;
        if(lv->model->item(i,4)->text() == "UDP")
            udp_count ++;
        if(lv->model->item(i,4)->text() == "ARP")
            arp_count ++;
    }
    coutv->show();
    coutv->setupData(tcp_count,udp_count,arp_count,total_count);
}
