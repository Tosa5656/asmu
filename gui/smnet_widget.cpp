/**
 * @file smnet_widget.cpp
 * @brief Реализация виджета smnet
 * @author Tosa5656
 * @date 1 марта, 2026
 */
#include "smnet_widget.h"
#include "../api/include/asmu.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLabel>
#include <QMessageBox>
#include <QHeaderView>

SmnetWidget::SmnetWidget(QWidget* parent)
    : QWidget(parent)
    , scan_group_(nullptr)
    , start_port_spin_(nullptr)
    , end_port_spin_(nullptr)
    , scan_button_(nullptr)
    , ports_table_(nullptr)
    , connections_group_(nullptr)
    , connections_button_(nullptr)
    , connections_table_(nullptr)
    , stats_group_(nullptr)
    , interfaces_button_(nullptr)
    , stats_button_(nullptr)
    , refresh_button_(nullptr)
    , stats_output_(nullptr)
{
    setupUi();
}

SmnetWidget::~SmnetWidget()
{
}

void SmnetWidget::setupUi()
{
    QVBoxLayout* main_layout = new QVBoxLayout(this);

    scan_group_ = new QGroupBox("Сканирование портов", this);
    QVBoxLayout* scan_layout = new QVBoxLayout(scan_group_);

    QHBoxLayout* port_range_layout = new QHBoxLayout();
    start_port_spin_ = new QSpinBox(this);
    start_port_spin_->setRange(1, 65535);
    start_port_spin_->setValue(1);
    end_port_spin_ = new QSpinBox(this);
    end_port_spin_->setRange(1, 65535);
    end_port_spin_->setValue(1024);
    scan_button_ = new QPushButton("Сканировать", this);
    connect(scan_button_, &QPushButton::clicked, this, &SmnetWidget::onScanPorts);

    port_range_layout->addWidget(new QLabel("От порта:", this));
    port_range_layout->addWidget(start_port_spin_);
    port_range_layout->addWidget(new QLabel("До порта:", this));
    port_range_layout->addWidget(end_port_spin_);
    port_range_layout->addWidget(scan_button_);
    port_range_layout->addStretch();
    scan_layout->addLayout(port_range_layout);

    ports_table_ = new QTableWidget(this);
    ports_table_->setColumnCount(4);
    ports_table_->setHorizontalHeaderLabels({"Порт", "Сервис", "Состояние", "Протокол"});
    ports_table_->horizontalHeader()->setStretchLastSection(true);
    ports_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    scan_layout->addWidget(ports_table_);

    main_layout->addWidget(scan_group_);

    connections_group_ = new QGroupBox("Активные соединения", this);
    QVBoxLayout* connections_layout = new QVBoxLayout(connections_group_);

    connections_button_ = new QPushButton("Показать соединения", this);
    connect(connections_button_, &QPushButton::clicked, this, &SmnetWidget::onShowConnections);
    connections_layout->addWidget(connections_button_);

    connections_table_ = new QTableWidget(this);
    connections_table_->setColumnCount(5);
    connections_table_->setHorizontalHeaderLabels({"Локальный адрес", "Удалённый адрес", "Протокол", "Состояние", "Порты"});
    connections_table_->horizontalHeader()->setStretchLastSection(true);
    connections_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    connections_layout->addWidget(connections_table_);

    main_layout->addWidget(connections_group_);

    stats_group_ = new QGroupBox("Статистика и интерфейсы", this);
    QVBoxLayout* stats_layout = new QVBoxLayout(stats_group_);

    QHBoxLayout* stats_buttons_layout = new QHBoxLayout();
    interfaces_button_ = new QPushButton("Интерфейсы", this);
    stats_button_ = new QPushButton("Статистика", this);
    refresh_button_ = new QPushButton("Обновить", this);
    connect(interfaces_button_, &QPushButton::clicked, this, &SmnetWidget::onShowInterfaces);
    connect(stats_button_, &QPushButton::clicked, this, &SmnetWidget::onShowStats);
    connect(refresh_button_, &QPushButton::clicked, this, &SmnetWidget::onRefresh);

    stats_buttons_layout->addWidget(interfaces_button_);
    stats_buttons_layout->addWidget(stats_button_);
    stats_buttons_layout->addWidget(refresh_button_);
    stats_buttons_layout->addStretch();
    stats_layout->addLayout(stats_buttons_layout);

    stats_output_ = new QTextEdit(this);
    stats_output_->setReadOnly(true);
    stats_output_->setMaximumHeight(200);
    stats_layout->addWidget(stats_output_);

    main_layout->addWidget(stats_group_);
}

void SmnetWidget::onScanPorts()
{
    int start = start_port_spin_->value();
    int end = end_port_spin_->value();

    if (start > end)
    {
        QMessageBox::warning(this, "Ошибка", "Начальный порт не может быть больше конечного");
        return;
    }

    ports_table_->setRowCount(0);
    emit statusMessage("Сканирование портов " + QString::number(start) + "-" + QString::number(end) + "...");

    Asmu::NetworkMonitor net_mon;
    auto result = net_mon.scanPorts(start, end);

    if (result.success())
    {
        for (const auto& port : result.data)
        {
            int row = ports_table_->rowCount();
            ports_table_->insertRow(row);
            ports_table_->setItem(row, 0, new QTableWidgetItem(QString::number(port.port)));
            ports_table_->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(port.service)));
            ports_table_->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(port.state)));
            ports_table_->setItem(row, 3, new QTableWidgetItem(QString::fromStdString(port.protocol)));
        }
        emit statusMessage("Найдено портов: " + QString::number(result.data.size()));
    }
    else
    {
        QMessageBox::critical(this, "Ошибка", QString::fromStdString(result.message));
        emit statusMessage("Ошибка сканирования");
    }
}

void SmnetWidget::onShowConnections()
{
    connections_table_->setRowCount(0);
    emit statusMessage("Загрузка активных соединений...");

    Asmu::NetworkMonitor net_mon;
    auto result = net_mon.getActiveConnections();

    if (result.success())
    {
        for (const auto& conn : result.data)
        {
            int row = connections_table_->rowCount();
            connections_table_->insertRow(row);
            connections_table_->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(conn.local_address)));
            connections_table_->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(conn.remote_address)));
            connections_table_->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(conn.protocol)));
            connections_table_->setItem(row, 3, new QTableWidgetItem(QString::fromStdString(conn.state)));
            connections_table_->setItem(row, 4, new QTableWidgetItem(
                QString::number(conn.local_port) + " → " + QString::number(conn.remote_port)));
        }
        emit statusMessage("Активных соединений: " + QString::number(result.data.size()));
    }
    else
    {
        QMessageBox::critical(this, "Ошибка", QString::fromStdString(result.message));
        emit statusMessage("Ошибка получения соединений");
    }
}

void SmnetWidget::onShowInterfaces()
{
    stats_output_->clear();
    emit statusMessage("Загрузка информации об интерфейсах...");

    Asmu::NetworkMonitor net_mon;
    auto result = net_mon.getNetworkInterfaces();

    if (result.success())
    {
        QString output;
        for (const auto& iface : result.data)
        {
            output += "Интерфейс: " + QString::fromStdString(iface.name) + "\n";
            output += "  Адрес: " + QString::fromStdString(iface.address) + "\n";
            output += "  Маска: " + QString::fromStdString(iface.netmask) + "\n";
            output += "  MAC: " + QString::fromStdString(iface.mac_address) + "\n";
            output += "  Статус: " + QString(iface.is_up ? "UP" : "DOWN") + "\n";
            output += "  RX: " + QString::number(iface.rx_bytes) + " байт\n";
            output += "  TX: " + QString::number(iface.tx_bytes) + " байт\n\n";
        }
        stats_output_->setText(output);
        emit statusMessage("Интерфейсов: " + QString::number(result.data.size()));
    }
    else
    {
        QMessageBox::critical(this, "Ошибка", QString::fromStdString(result.message));
    }
}

void SmnetWidget::onShowStats()
{
    stats_output_->clear();
    emit statusMessage("Загрузка статистики сети...");

    Asmu::NetworkMonitor net_mon;
    auto result = net_mon.getNetworkStats();

    if (result.success())
    {
        QString output;
        output += "=== Общая статистика сети ===\n\n";
        output += "Получено байт: " + QString::number(result.data.total_bytes_received) + "\n";
        output += "Отправлено байт: " + QString::number(result.data.total_bytes_sent) + "\n";
        output += "Получено пакетов: " + QString::number(result.data.total_packets_received) + "\n";
        output += "Отправлено пакетов: " + QString::number(result.data.total_packets_sent) + "\n";
        stats_output_->setText(output);
        emit statusMessage("Статистика загружена");
    }
    else
    {
        QMessageBox::critical(this, "Ошибка", QString::fromStdString(result.message));
    }
}

void SmnetWidget::onRefresh()
{
    onShowConnections();
    onShowStats();
}

void SmnetWidget::clearResults()
{
    ports_table_->setRowCount(0);
    connections_table_->setRowCount(0);
    stats_output_->clear();
}
