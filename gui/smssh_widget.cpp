/**
 * @file smssh_widget.cpp
 * @brief Реализация виджета smssh
 * @author Tosa5656
 * @date 1 марта, 2026
 */
#include "smssh_widget.h"
#include "../api/include/asmu.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QFileDialog>

SmsshWidget::SmsshWidget(QWidget* parent)
    : QWidget(parent)
    , config_group_(nullptr)
    , config_path_edit_(nullptr)
    , browse_config_button_(nullptr)
    , analyze_button_(nullptr)
    , generate_button_(nullptr)
    , log_group_(nullptr)
    , log_path_edit_(nullptr)
    , browse_log_button_(nullptr)
    , parse_button_(nullptr)
    , monitor_button_(nullptr)
    , clear_button_(nullptr)
    , output_text_(nullptr)
{
    setupUi();
}

SmsshWidget::~SmsshWidget()
{
}

void SmsshWidget::setupUi()
{
    QVBoxLayout* main_layout = new QVBoxLayout(this);

    config_group_ = new QGroupBox("Конфигурация SSH", this);
    QVBoxLayout* config_layout = new QVBoxLayout(config_group_);

    QHBoxLayout* config_path_layout = new QHBoxLayout();
    config_path_edit_ = new QLineEdit(this);
    config_path_edit_->setPlaceholderText("/etc/ssh/sshd_config");
    config_path_edit_->setText("/etc/ssh/sshd_config");
    browse_config_button_ = new QPushButton("Обзор...", this);
    connect(browse_config_button_, &QPushButton::clicked, this, &SmsshWidget::onBrowseConfig);
    config_path_layout->addWidget(new QLabel("Путь к конфигу:", this));
    config_path_layout->addWidget(config_path_edit_);
    config_path_layout->addWidget(browse_config_button_);
    config_layout->addLayout(config_path_layout);

    QHBoxLayout* config_buttons_layout = new QHBoxLayout();
    analyze_button_ = new QPushButton("Анализировать", this);
    generate_button_ = new QPushButton("Сгенерировать безопасный конфиг", this);
    connect(analyze_button_, &QPushButton::clicked, this, &SmsshWidget::onAnalyzeConfig);
    connect(generate_button_, &QPushButton::clicked, this, &SmsshWidget::onGenerateConfig);
    config_buttons_layout->addWidget(analyze_button_);
    config_buttons_layout->addWidget(generate_button_);
    config_buttons_layout->addStretch();
    config_layout->addLayout(config_buttons_layout);

    main_layout->addWidget(config_group_);

    log_group_ = new QGroupBox("Мониторинг и анализ логов", this);
    QVBoxLayout* log_layout = new QVBoxLayout(log_group_);

    QHBoxLayout* log_path_layout = new QHBoxLayout();
    log_path_edit_ = new QLineEdit(this);
    log_path_edit_->setPlaceholderText("/var/log/auth.log");
    log_path_edit_->setText("/var/log/auth.log");
    browse_log_button_ = new QPushButton("Обзор...", this);
    connect(browse_log_button_, &QPushButton::clicked, this, &SmsshWidget::onBrowseLog);
    log_path_layout->addWidget(new QLabel("Путь к логу:", this));
    log_path_layout->addWidget(log_path_edit_);
    log_path_layout->addWidget(browse_log_button_);
    log_layout->addLayout(log_path_layout);

    QHBoxLayout* log_buttons_layout = new QHBoxLayout();
    parse_button_ = new QPushButton("Разобрать лог", this);
    monitor_button_ = new QPushButton("Мониторинг атак", this);
    connect(parse_button_, &QPushButton::clicked, this, &SmsshWidget::onParseLog);
    connect(monitor_button_, &QPushButton::clicked, this, &SmsshWidget::onMonitorAttacks);
    log_buttons_layout->addWidget(parse_button_);
    log_buttons_layout->addWidget(monitor_button_);
    log_buttons_layout->addStretch();
    log_layout->addLayout(log_buttons_layout);

    main_layout->addWidget(log_group_);

    QHBoxLayout* output_controls_layout = new QHBoxLayout();
    clear_button_ = new QPushButton("Очистить", this);
    connect(clear_button_, &QPushButton::clicked, this, &SmsshWidget::onClearOutput);
    output_controls_layout->addWidget(new QLabel("Вывод:", this));
    output_controls_layout->addStretch();
    output_controls_layout->addWidget(clear_button_);
    main_layout->addLayout(output_controls_layout);

    output_text_ = new QTextEdit(this);
    output_text_->setReadOnly(true);
    output_text_->setFont(QFont("Monospace", 9));
    main_layout->addWidget(output_text_);
}

void SmsshWidget::onAnalyzeConfig()
{
    QString path = config_path_edit_->text().trimmed();
    if (path.isEmpty())
    {
        QMessageBox::warning(this, "Ошибка", "Укажите путь к конфигурации SSH");
        return;
    }

    output_text_->clear();
    emit statusMessage("Анализ конфигурации " + path + "...");

    Asmu::SSHSecurity ssh_sec;
    auto result = ssh_sec.analyzeConfiguration(path.toStdString());

    if (result.success())
    {
        QString output = "=== Анализ конфигурации SSH ===\n\n";
        output += "Оценка безопасности: " + QString::number(result.data.security_score) + "/100\n";
        output += "Уровень риска: " + QString::fromStdString(result.data.overall_risk_level) + "\n";
        output += "Критичных проблем: " + QString::number(result.data.critical_issues) + "\n";
        output += "Высоких проблем: " + QString::number(result.data.high_issues) + "\n";
        output += "Средних проблем: " + QString::number(result.data.medium_issues) + "\n";
        output += "Низких проблем: " + QString::number(result.data.low_issues) + "\n\n";

        if (!result.data.issues.empty())
        {
            output += "Обнаруженные проблемы:\n";
            for (const auto& issue : result.data.issues)
            {
                output += "  • [" + QString::fromStdString(issue.severity) + "] ";
                output += QString::fromStdString(issue.parameter) + ": ";
                output += QString::fromStdString(issue.description) + "\n";
            }
            output += "\n";
        }

        if (!result.data.recommendations.empty())
        {
            output += "Рекомендации:\n";
            for (const auto& rec : result.data.recommendations)
            {
                output += "  ✓ " + QString::fromStdString(rec.parameter) + ": ";
                output += QString::fromStdString(rec.rationale) + "\n";
            }
        }

        output_text_->setText(output);
        emit statusMessage("Анализ завершён. Оценка: " + QString::number(result.data.security_score) + "/100");
    }
    else
    {
        QMessageBox::critical(this, "Ошибка", QString::fromStdString(result.message));
        emit statusMessage("Ошибка анализа конфигурации");
    }
}

void SmsshWidget::onGenerateConfig()
{
    QString save_path = QFileDialog::getSaveFileName(this, "Сохранить конфигурацию", "sshd_config_secure", "Config files (*.conf *.config);;All files (*)");
    if (save_path.isEmpty())
        return;

    emit statusMessage("Генерация безопасной конфигурации...");

    Asmu::SSHSecurity ssh_sec;
    auto result = ssh_sec.generateSecureConfig(save_path.toStdString());

    if (result.success())
    {
        QMessageBox::information(this, "Успех", "Безопасная конфигурация сохранена в:\n" + save_path);
        output_text_->setText("Конфигурация сгенерирована:\n" + save_path + "\n\nПрименить:\nsudo cp " + save_path + " /etc/ssh/sshd_config\nsudo systemctl restart sshd");
        emit statusMessage("Конфигурация сгенерирована");
    }
    else
    {
        QMessageBox::critical(this, "Ошибка", QString::fromStdString(result.message));
        emit statusMessage("Ошибка генерации конфигурации");
    }
}

void SmsshWidget::onParseLog()
{
    QString path = log_path_edit_->text().trimmed();
    if (path.isEmpty())
    {
        QMessageBox::warning(this, "Ошибка", "Укажите путь к лог-файлу");
        return;
    }

    output_text_->clear();
    emit statusMessage("Разбор лога " + path + "...");

    Asmu::SSHSecurity ssh_sec;
    auto result = ssh_sec.detectAttacks(path.toStdString());

    if (result.success())
    {
        QString output = "=== Анализ SSH логов ===\n\n";
        output += "Обнаружено атак: " + QString::number(result.data.size()) + "\n\n";

        int failed = 0, brute_force = 0;
        for (const auto& attack : result.data)
        {
            if (attack.attack_type == "brute_force")
                brute_force++;
            else
                failed++;
        }

        output += "Brute force атак: " + QString::number(brute_force) + "\n";
        output += "Других атак: " + QString::number(failed) + "\n\n";

        if (!result.data.empty())
        {
            output += "Детали:\n";
            for (const auto& attack : result.data)
            {
                output += "  ⚠ " + QString::fromStdString(attack.attack_type);
                output += " от " + QString::fromStdString(attack.ip_address) + "\n";
            }
        }

        output_text_->setText(output);
        emit statusMessage("Лог разобран. Атак: " + QString::number(result.data.size()));
    }
    else
    {
        QMessageBox::critical(this, "Ошибка", QString::fromStdString(result.message));
        emit statusMessage("Ошибка разбора лога");
    }
}

void SmsshWidget::onMonitorAttacks()
{
    QString path = log_path_edit_->text().trimmed();
    if (path.isEmpty())
    {
        QMessageBox::warning(this, "Ошибка", "Укажите путь к лог-файлу");
        return;
    }

    output_text_->clear();
    emit statusMessage("Обнаружение атак в " + path + "...");

    Asmu::SSHSecurity ssh_sec;
    auto result = ssh_sec.detectAttacks(path.toStdString());

    if (result.success())
    {
        QString output = "=== Обнаруженные атаки ===\n\n";

        if (result.data.empty())
        {
            output += "Атак не обнаружено.\n";
        }
        else
        {
            for (const auto& attack : result.data)
            {
                output += "Тип: " + QString::fromStdString(attack.attack_type) + "\n";
                output += "IP: " + QString::fromStdString(attack.ip_address) + "\n";
                output += "Время: " + QString::fromStdString(attack.timestamp) + "\n";
                output += "Описание: " + QString::fromStdString(attack.description) + "\n";
                output += "Серьёзность: " + QString::fromStdString(attack.severity) + "\n";
                output += "Рекомендация: " + QString::fromStdString(attack.recommended_action) + "\n\n";
            }
        }

        output_text_->setText(output);
        emit statusMessage("Обнаружено атак: " + QString::number(result.data.size()));
    }
    else
    {
        QMessageBox::critical(this, "Ошибка", QString::fromStdString(result.message));
        emit statusMessage("Ошибка обнаружения атак");
    }
}

void SmsshWidget::onBrowseConfig()
{
    QString path = QFileDialog::getOpenFileName(this, "Выберите конфигурацию SSH", "/etc/ssh", "Config files (sshd_config *);;All files (*)");
    if (!path.isEmpty())
    {
        config_path_edit_->setText(path);
    }
}

void SmsshWidget::onBrowseLog()
{
    QString path = QFileDialog::getOpenFileName(this, "Выберите лог-файл", "/var/log", "Log files (*.log auth.log);;All files (*)");
    if (!path.isEmpty())
    {
        log_path_edit_->setText(path);
    }
}

void SmsshWidget::onClearOutput()
{
    output_text_->clear();
    emit statusMessage("Вывод очищен");
}
