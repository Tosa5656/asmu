/**
 * @file smpass_widget.h
 * @brief Виджет для работы с утилитой smpass
 * @author Tosa5656
 * @date 1 марта, 2026
 */
#pragma once

#include <QWidget>
#include <QPushButton>
#include <QLineEdit>
#include <QTextEdit>
#include <QTableWidget>
#include <QComboBox>
#include <QGroupBox>

/**
 * @brief Виджет управления паролями (smpass)
 *
 * Предоставляет интерфейс для хранения паролей с шифрованием,
 * хэширования строк и управления записями.
 */
class SmpassWidget : public QWidget
{
    Q_OBJECT

public:
    explicit SmpassWidget(QWidget* parent = nullptr);
    ~SmpassWidget();

signals:
    /**
     * @brief Сигнал для обновления статус-бара
     * @param message Сообщение статуса
     */
    void statusMessage(const QString& message);

private slots:
    void onAddPassword();
    void onDeletePassword();
    void onSearchPassword();
    void onRefreshList();
    void onHashString();
    void onEncryptString();
    void onTableItemSelected();
    void onShowPassword();

private:
    void setupUi();
    void loadPasswords();
    void clearInputFields();

    QTableWidget* password_table_;

    QLineEdit* service_edit_;
    QLineEdit* username_edit_;
    QLineEdit* password_edit_;
    QLineEdit* search_edit_;

    QPushButton* add_button_;
    QPushButton* delete_button_;
    QPushButton* refresh_button_;
    QPushButton* search_button_;
    QPushButton* show_password_button_;

    QGroupBox* hash_group_;
    QLineEdit* hash_input_;
    QComboBox* hash_algorithm_;
    QPushButton* hash_button_;
    QTextEdit* hash_output_;

    QString selected_service_;
};
