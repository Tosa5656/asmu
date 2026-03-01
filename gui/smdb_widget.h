/**
 * @file smdb_widget.h
 * @brief Виджет для работы с утилитой smdb
 * @author Tosa5656
 * @date 1 марта, 2026
 */
#pragma once

#include <QWidget>
#include <QPushButton>
#include <QLineEdit>
#include <QTextEdit>
#include <QTableWidget>
#include <QGroupBox>

/**
 * @brief Виджет базы атак MITRE ATT&CK (smdb)
 *
 * Предоставляет интерфейс для поиска и просмотра информации
 * о техниках атак из базы MITRE ATT&CK.
 */
class SmdbWidget : public QWidget
{
    Q_OBJECT

public:
    explicit SmdbWidget(QWidget* parent = nullptr);
    ~SmdbWidget();

signals:
    void statusMessage(const QString& message);

private slots:
    void onListAttacks();
    void onSearchAttacks();
    void onShowAttackInfo();
    void onShowTools();
    void onTableItemSelected();
    void onClearOutput();

private:
    void setupUi();

    QGroupBox* search_group_;
    QLineEdit* search_edit_;
    QPushButton* search_button_;
    QPushButton* list_button_;

    QTableWidget* attacks_table_;

    QGroupBox* details_group_;
    QPushButton* show_info_button_;
    QPushButton* show_tools_button_;
    QPushButton* clear_button_;
    QTextEdit* details_text_;

    QString selected_attack_id_;
};
