/**
 * @file smnet_widget.h
 * @brief Виджет для работы с утилитой smnet
 * @author Tosa5656
 * @date 1 марта, 2026
 */
#pragma once

#include <QWidget>
#include <QPushButton>
#include <QTableWidget>
#include <QTextEdit>
#include <QSpinBox>
#include <QGroupBox>
#include <QComboBox>

/**
 * @brief Виджет мониторинга сети (smnet)
 *
 * Предоставляет интерфейс для сканирования портов,
 * просмотра активных соединений и статистики сети.
 */
class SmnetWidget : public QWidget
{
    Q_OBJECT

public:
    explicit SmnetWidget(QWidget* parent = nullptr);
    ~SmnetWidget();

signals:
    void statusMessage(const QString& message);

private slots:
    void onScanPorts();
    void onShowConnections();
    void onShowInterfaces();
    void onShowStats();
    void onRefresh();

private:
    void setupUi();
    void clearResults();

    QGroupBox* scan_group_;
    QSpinBox* start_port_spin_;
    QSpinBox* end_port_spin_;
    QPushButton* scan_button_;
    QTableWidget* ports_table_;

    QGroupBox* connections_group_;
    QPushButton* connections_button_;
    QTableWidget* connections_table_;

    QGroupBox* stats_group_;
    QPushButton* interfaces_button_;
    QPushButton* stats_button_;
    QPushButton* refresh_button_;
    QTextEdit* stats_output_;
};
