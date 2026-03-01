/**
 * @file smssh_widget.h
 * @brief Виджет для работы с утилитой smssh
 * @author Tosa5656
 * @date 1 марта, 2026
 */
#pragma once

#include <QWidget>
#include <QPushButton>
#include <QLineEdit>
#include <QTextEdit>
#include <QGroupBox>
#include <QCheckBox>

/**
 * @brief Виджет безопасности SSH (smssh)
 *
 * Предоставляет интерфейс для анализа конфигурации SSH,
 * мониторинга атак и генерации безопасных настроек.
 */
class SmsshWidget : public QWidget
{
    Q_OBJECT

public:
    explicit SmsshWidget(QWidget* parent = nullptr);
    ~SmsshWidget();

signals:
    void statusMessage(const QString& message);

private slots:
    void onAnalyzeConfig();
    void onGenerateConfig();
    void onParseLog();
    void onMonitorAttacks();
    void onBrowseConfig();
    void onBrowseLog();
    void onClearOutput();

private:
    void setupUi();

    QGroupBox* config_group_;
    QLineEdit* config_path_edit_;
    QPushButton* browse_config_button_;
    QPushButton* analyze_button_;
    QPushButton* generate_button_;

    QGroupBox* log_group_;
    QLineEdit* log_path_edit_;
    QPushButton* browse_log_button_;
    QPushButton* parse_button_;
    QPushButton* monitor_button_;

    QPushButton* clear_button_;
    QTextEdit* output_text_;
};
