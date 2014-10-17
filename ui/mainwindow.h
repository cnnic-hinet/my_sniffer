#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QMenu>
#include <QToolBar>
#include <QLabel>
#include <QMenuBar>
#include <QComboBox>
#include <QPushButton>
#include <QAction>
#include <QLineEdit>
#include <QCloseEvent>
#include "ui/pkt_list_view.h"
//#include "ui/pkt_tree_view.h"
#include "ui/pkt_analysis_view.h"
#include "ui/select_nif_dlg.h"
#include "ui/pkt_count.h"
#include "sniffer/sniffer_manager.h"
class QAction;
class QMenu;
class QToolBar;
class MainWindow : public QMainWindow
{
        Q_OBJECT

    public:
        MainWindow(QWidget *parent = 0);
        ~MainWindow();

        void rcv_pkt_info(pkt_info_t *pkt_info);
    protected:
        void closeEvent(QCloseEvent *event);
    private:
        void create_toolbars();
        void create_actions();
        void create_menu();
        void create_statusbar();
        //slots:
        void select_nif();
        void start();
        void stop();
        void restart();
        void proc_selected_item(const QItemSelection &selected);
        void find();
        void pro_find();
        void ip_find();
//        void dst_ip_find();
        void port_find();
        bool checkpro(int n, QString &str);
//        void dst_port_find();
        void return_lv();
        void count_view();
    private:
        sniffer_manager *smgr;
        int current_pkt_num;
        pkt_list_view *lv;
        pkt_tree_view *tv;
        pkt_analysis_view *pav;
        pkt_count *coutv;
        QToolBar *tb_work;
        QLabel *statusLabel;
        QComboBox *find_box;
        QLabel *applay_label;
        QLineEdit *find_edit;
        QPushButton *button;
        QPushButton *return_button;
        QMenu *menu;
        QAction *act_start;
        QAction *act_stop;
        QAction *act_select_nif;
        QAction *act_restart;
        QAction *act_count;

};

#endif // MAINWINDOW_H
