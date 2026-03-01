/**
 * @file smlog_widget.cpp
 * @brief Реализация виджета smlog
 * @author Tosa5656
 * @date 1 марта, 2026
 */
#include "smlog_widget.h"
#include "../api/include/asmu.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLabel>
#include <QMessageBox>
#include <QFileDialog>

SmlogWidget::SmlogWidget(QWidget* parent)
    : QWidget(parent)
    , read_group_(nullptr)
    , log_path_edit_(nullptr)
    , browse_button_(nullptr)
    , lines_spin_(nullptr)
    , read_button_(nullptr)
    , search_group_(nullptr)
    , search_keyword_edit_(nullptr)
    , search_button_(nullptr)
    , report_group_(nullptr)
    , report_type_combo_(nullptr)
    , generate_button_(nullptr)
    , clear_button_(nullptr)
    , output_text_(nullptr)
{
    setupUi();
}

SmlogWidget::~SmlogWidget()
{
}

void SmlogWidget::setupUi()
{
    QVBoxLayout* main_layout = new QVBoxLayout(this);

    read_group_ = new QGroupBox("Чтение лог-файла", this);
    QVBoxLayout* read_layout = new QVBoxLayout(read_group_);

    QHBoxLayout* path_layout = new QHBoxLayout();
    log_path_edit_ = new QLineEdit(this);
    log_path_edit_->setPlaceholderText("/var/log/syslog");
    log_path_edit_->setText("/var/log/syslog");
    browse_button_ = new QPushButton("Обзор...", this);
    connect(browse_button_, &QPushButton::clicked, this, &SmlogWidget::onBrowseLogFile);
    path_layout->addWidget(new QLabel("Путь:", this));
    path_layout->addWidget(log_path_edit_);
    path_layout->addWidget(browse_button_);
    read_layout->addLayout(path_layout);

    QHBoxLayout* read_controls_layout = new QHBoxLayout();
    lines_spin_ = new QSpinBox(this);
    lines_spin_->setRange(10, 10000);
    lines_spin_->setValue(100);
    read_button_ = new QPushButton("Прочитать", this);
    connect(read_button_, &QPushButton::clicked, this, &SmlogWidget::onReadLog);
    read_controls_layout->addWidget(new QLabel("Строк:", this));
    read_controls_layout->addWidget(lines_spin_);
    read_controls_layout->addWidget(read_button_);
    read_controls_layout->addStretch();
    read_layout->addLayout(read_controls_layout);

    main_layout->addWidget(read_group_);

    search_group_ = new QGroupBox("Поиск в логах", this);
    QHBoxLayout* search_layout = new QHBoxLayout(search_group_);
    search_keyword_edit_ = new QLineEdit(this);
    search_keyword_edit_->setPlaceholderText("Введите ключевое слово для поиска...");
    search_button_ = new QPushButton("Искать", this);
    connect(search_button_, &QPushButton::clicked, this, &SmlogWidget::onSearchLog);
    search_layout->addWidget(new QLabel("Ключевое слово:", this));
    search_layout->addWidget(search_keyword_edit_);
    search_layout->addWidget(search_button_);

    main_layout->addWidget(search_group_);

    report_group_ = new QGroupBox("Отчёты", this);
    QHBoxLayout* report_layout = new QHBoxLayout(report_group_);
    report_type_combo_ = new QComboBox(this);
    report_type_combo_->addItem("Безопасность");
    report_type_combo_->addItem("Система");
    report_type_combo_->addItem("Журнал");
    generate_button_ = new QPushButton("Сгенерировать отчёт", this);
    connect(generate_button_, &QPushButton::clicked, this, &SmlogWidget::onGenerateReport);
    report_layout->addWidget(new QLabel("Тип отчёта:", this));
    report_layout->addWidget(report_type_combo_);
    report_layout->addWidget(generate_button_);
    report_layout->addStretch();

    main_layout->addWidget(report_group_);

    QHBoxLayout* output_controls_layout = new QHBoxLayout();
    clear_button_ = new QPushButton("Очистить", this);
    connect(clear_button_, &QPushButton::clicked, this, &SmlogWidget::onClearOutput);
    output_controls_layout->addWidget(new QLabel("Вывод:", this));
    output_controls_layout->addStretch();
    output_controls_layout->addWidget(clear_button_);
    main_layout->addLayout(output_controls_layout);

    output_text_ = new QTextEdit(this);
    output_text_->setReadOnly(true);
    output_text_->setFont(QFont("Monospace", 9));
    main_layout->addWidget(output_text_);
}

void SmlogWidget::onReadLog()
{
    QString path = log_path_edit_->text().trimmed();
    if (path.isEmpty())
    {
        QMessageBox::warning(this, "Ошибка", "Укажите путь к лог-файлу");
        return;
    }

    int lines = lines_spin_->value();
    output_text_->clear();
    emit statusMessage("Чтение " + path + "...");

    Asmu::LogAnalyzer log_analyzer;
    Asmu::LogFilter filter;
    auto result = log_analyzer.readLogFile(path.toStdString(), filter, lines);

    if (result.success())
    {
        QString output;
        for (const auto& entry : result.data)
        {
            output += QString::fromStdString(entry.timestamp) + " ";
            output += QString::fromStdString(entry.level) + " ";
            output += QString::fromStdString(entry.message) + "\n";
        }
        output_text_->setText(output);
        emit statusMessage("Прочитано строк: " + QString::number(result.data.size()));
    }
    else
    {
        QMessageBox::critical(this, "Ошибка", QString::fromStdString(result.message));
        emit statusMessage("Ошибка чтения лога");
    }
}

void SmlogWidget::onSearchLog()
{
    QString path = log_path_edit_->text().trimmed();
    QString keyword = search_keyword_edit_->text().trimmed();

    if (path.isEmpty() || keyword.isEmpty())
    {
        QMessageBox::warning(this, "Ошибка", "Укажите путь и ключевое слово");
        return;
    }

    output_text_->clear();
    emit statusMessage("Поиск '" + keyword + "' в " + path + "...");

    Asmu::LogAnalyzer log_analyzer;
    Asmu::LogFilter filter;
    auto result = log_analyzer.searchLogFile(path.toStdString(), keyword.toStdString(), filter);

    if (result.success())
    {
        QString output;
        for (const auto& entry : result.data)
        {
            output += QString::fromStdString(entry.timestamp) + " ";
            output += QString::fromStdString(entry.level) + " ";
            output += QString::fromStdString(entry.message) + "\n";
        }
        output_text_->setText(output);
        emit statusMessage("Найдено совпадений: " + QString::number(result.data.size()));
    }
    else
    {
        QMessageBox::critical(this, "Ошибка", QString::fromStdString(result.message));
        emit statusMessage("Ошибка поиска");
    }
}

void SmlogWidget::onGenerateReport()
{
    QString report_type = report_type_combo_->currentText();
    QString path = log_path_edit_->text().trimmed();

    if (path.isEmpty())
        path = "/var/log/syslog";

    output_text_->clear();
    emit statusMessage("Генерация отчёта: " + report_type + "...");

    Asmu::LogAnalyzer log_analyzer;
    Asmu::LogFilter filter;

    if (report_type == "Безопасность")
        filter.keyword = "fail|error|denied|attack";
    else if (report_type == "Система")
        filter.source = "systemd";

    auto result = log_analyzer.readLogFile(path.toStdString(), filter, 1000);

    if (result.success())
    {
        QString output = "=== Отчёт: " + report_type + " ===\n\n";
        output += "Всего записей: " + QString::number(result.data.size()) + "\n\n";

        for (const auto& entry : result.data)
        {
            output += QString::fromStdString(entry.timestamp) + " ";
            output += QString::fromStdString(entry.level) + " ";
            output += QString::fromStdString(entry.message) + "\n";
        }

        output_text_->setText(output);
        emit statusMessage("Отчёт сгенерирован: " + report_type);
    }
    else
    {
        QMessageBox::critical(this, "Ошибка", QString::fromStdString(result.message));
        emit statusMessage("Ошибка генерации отчёта");
    }
}

void SmlogWidget::onClearOutput()
{
    output_text_->clear();
    emit statusMessage("Вывод очищен");
}

void SmlogWidget::onBrowseLogFile()
{
    QString path = QFileDialog::getOpenFileName(this, "Выберите лог-файл", "/var/log", "Log files (*.log);;All files (*)");
    if (!path.isEmpty())
    {
        log_path_edit_->setText(path);
    }
}
