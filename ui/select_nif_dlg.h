#ifndef SELECT_NIF_DLG_H
#define SELECT_NIF_DLG_H

#include <QDialog>
#include <QListView>
#include <QStandardItemModel>
#include <QDialogButtonBox>
#include <QCheckBox>
#include <tins/tins.h>
#include <vector>
#include <QPushButton>
#include <QComboBox>
#include <QString>
class select_nif_dlg : public QDialog
{
        Q_OBJECT
    public:
        explicit select_nif_dlg(QWidget *parent = 0);
        Tins::NetworkInterface get_selected();
        QString get_select_filter();
        bool use_promisc();

    signals:

    private slots:
//        void set_choose(QStandardItem *item);
        void set_choose_filter(QStandardItem *item);
        void set_choose(int);
    private:
        void setup_nif_info();
        void setup_filter_info();
    private:

//        QListView *nif_list_view;//选择网卡，考虑使用下拉按钮
        QComboBox *nif_combo_view;
        QListView *filter_list_view;//选择过滤条件，使用复选框
        QStandardItemModel *model_nif;
        QStandardItemModel *model_filter;
        QCheckBox *cb_promisc;
        QDialogButtonBox *btnbox;
        QPushButton *btnok;
        QPushButton *btncancle;

        std::vector<Tins::NetworkInterface> all_nif;
        std::vector<QString> all_filter;
        int selected;
        int selected_filter;
};

#endif // SELECT_NIF_DLG_H
