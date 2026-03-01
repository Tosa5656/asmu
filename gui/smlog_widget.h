/**
 * @file smlog_widget.h
 * @brief Виджет для работы с утилитой smlog
 * @author Tosa5656
 * @date 1 марта, 2026
 */
#pragma once

#include <QWidget>
#include <QPushButton>
#include <QLineEdit>
#include <QTextEdit>
#include <QComboBox>
#include <QSpinBox>
#include <QGroupBox>

/**
 * @brief Виджет анализа логов (smlog)
 *
 * Предоставляет интерфейс для чтения системных логов,
 * поиска по ключевым словам и генерации отчётов.
 */
class SmlogWidget : public QWidget
{
    Q_OBJECT

public:
    explicit SmlogWidget(QWidget* parent = nullptr);
    ~SmlogWidget();

signals:
    void statusMessage(const QString& message);

private slots:
    void onReadLog();
    void onSearchLog();
    void onGenerateReport();
    void onClearOutput();
    void onBrowseLogFile();

private:
    void setupUi();

    QGroupBox* read_group_;
    QLineEdit* log_path_edit_;
    QPushButton* browse_button_;
    QSpinBox* lines_spin_;
    QPushButton* read_button_;

    QGroupBox* search_group_;
    QLineEdit* search_keyword_edit_;
    QPushButton* search_button_;

    QGroupBox* report_group_;
    QComboBox* report_type_combo_;
    QPushButton* generate_button_;

    QPushButton* clear_button_;
    QTextEdit* output_text_;
};
