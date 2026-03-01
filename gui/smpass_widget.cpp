/**
 * @file smpass_widget.cpp
 * @brief Реализация виджета smpass
 * @author Tosa5656
 * @date 1 марта, 2026
 */
#include "smpass_widget.h"
#include "../api/include/asmu.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLabel>
#include <QMessageBox>
#include <QHeaderView>
#include <QInputDialog>

SmpassWidget::SmpassWidget(QWidget* parent)
    : QWidget(parent)
    , password_table_(nullptr)
    , service_edit_(nullptr)
    , username_edit_(nullptr)
    , password_edit_(nullptr)
    , search_edit_(nullptr)
    , add_button_(nullptr)
    , delete_button_(nullptr)
    , refresh_button_(nullptr)
    , search_button_(nullptr)
    , show_password_button_(nullptr)
    , hash_group_(nullptr)
    , hash_input_(nullptr)
    , hash_algorithm_(nullptr)
    , hash_button_(nullptr)
    , hash_output_(nullptr)
{
    setupUi();
    loadPasswords();
}

SmpassWidget::~SmpassWidget()
{
}

void SmpassWidget::setupUi()
{
    QVBoxLayout* main_layout = new QVBoxLayout(this);

    QGroupBox* password_group = new QGroupBox("Управление паролями", this);
    QVBoxLayout* password_layout = new QVBoxLayout(password_group);

    password_table_ = new QTableWidget(this);
    password_table_->setColumnCount(4);
    password_table_->setHorizontalHeaderLabels({"Сервис", "Пользователь", "Создан", "Изменён"});
    password_table_->horizontalHeader()->setStretchLastSection(true);
    password_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    password_table_->setSelectionMode(QAbstractItemView::SingleSelection);
    password_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    connect(password_table_, &QTableWidget::itemSelectionChanged, this, &SmpassWidget::onTableItemSelected);
    password_layout->addWidget(password_table_);

    QHBoxLayout* search_layout = new QHBoxLayout();
    search_edit_ = new QLineEdit(this);
    search_edit_->setPlaceholderText("Поиск по сервису...");
    search_button_ = new QPushButton("Поиск", this);
    connect(search_button_, &QPushButton::clicked, this, &SmpassWidget::onSearchPassword);
    search_layout->addWidget(search_edit_);
    search_layout->addWidget(search_button_);
    password_layout->addLayout(search_layout);

    QFormLayout* form_layout = new QFormLayout();
    service_edit_ = new QLineEdit(this);
    username_edit_ = new QLineEdit(this);
    password_edit_ = new QLineEdit(this);
    password_edit_->setEchoMode(QLineEdit::Password);

    form_layout->addRow("Сервис:", service_edit_);
    form_layout->addRow("Пользователь:", username_edit_);
    form_layout->addRow("Пароль:", password_edit_);
    password_layout->addLayout(form_layout);

    QHBoxLayout* button_layout = new QHBoxLayout();
    add_button_ = new QPushButton("Добавить", this);
    delete_button_ = new QPushButton("Удалить", this);
    refresh_button_ = new QPushButton("Обновить", this);
    show_password_button_ = new QPushButton("Показать пароль", this);

    connect(add_button_, &QPushButton::clicked, this, &SmpassWidget::onAddPassword);
    connect(delete_button_, &QPushButton::clicked, this, &SmpassWidget::onDeletePassword);
    connect(refresh_button_, &QPushButton::clicked, this, &SmpassWidget::onRefreshList);
    connect(show_password_button_, &QPushButton::clicked, this, &SmpassWidget::onShowPassword);

    button_layout->addWidget(add_button_);
    button_layout->addWidget(delete_button_);
    button_layout->addWidget(show_password_button_);
    button_layout->addWidget(refresh_button_);
    password_layout->addLayout(button_layout);

    main_layout->addWidget(password_group);

    hash_group_ = new QGroupBox("Хэширование и шифрование", this);
    QVBoxLayout* hash_layout = new QVBoxLayout(hash_group_);

    QHBoxLayout* hash_input_layout = new QHBoxLayout();
    hash_input_ = new QLineEdit(this);
    hash_input_->setPlaceholderText("Введите строку для хэширования...");
    hash_algorithm_ = new QComboBox(this);
    hash_algorithm_->addItem("SHA256");
    hash_algorithm_->addItem("AES256");
    hash_button_ = new QPushButton("Хэшировать", this);
    connect(hash_button_, &QPushButton::clicked, this, &SmpassWidget::onHashString);

    hash_input_layout->addWidget(new QLabel("Строка:", this));
    hash_input_layout->addWidget(hash_input_);
    hash_input_layout->addWidget(new QLabel("Алгоритм:", this));
    hash_input_layout->addWidget(hash_algorithm_);
    hash_input_layout->addWidget(hash_button_);
    hash_layout->addLayout(hash_input_layout);

    hash_output_ = new QTextEdit(this);
    hash_output_->setReadOnly(true);
    hash_output_->setMaximumHeight(100);
    hash_output_->setPlaceholderText("Результат хэширования появится здесь...");
    hash_layout->addWidget(hash_output_);

    main_layout->addWidget(hash_group_);
}

void SmpassWidget::loadPasswords()
{
    password_table_->setRowCount(0);

    Asmu::PasswordManager pwd_mgr;
    auto result = pwd_mgr.listServices();

    if (!result.success())
    {
        emit statusMessage("Ошибка загрузки паролей: " + QString::fromStdString(result.message));
        return;
    }

    for (const auto& service : result.data)
    {
        auto entry_result = pwd_mgr.getPassword(service);
        if (entry_result.success())
        {
            int row = password_table_->rowCount();
            password_table_->insertRow(row);
            password_table_->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(entry_result.data.service)));
            password_table_->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(entry_result.data.username)));
            password_table_->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(entry_result.data.created_date)));
            password_table_->setItem(row, 3, new QTableWidgetItem(QString::fromStdString(entry_result.data.last_modified)));
        }
    }

    emit statusMessage("Загружено записей: " + QString::number(result.data.size()));
}

void SmpassWidget::onAddPassword()
{
    QString service = service_edit_->text().trimmed();
    QString username = username_edit_->text().trimmed();
    QString password = password_edit_->text();

    if (service.isEmpty() || username.isEmpty() || password.isEmpty())
    {
        QMessageBox::warning(this, "Ошибка", "Заполните все поля");
        return;
    }

    Asmu::PasswordManager pwd_mgr;
    auto result = pwd_mgr.addPassword(service.toStdString(), username.toStdString(), password.toStdString());

    if (result.success())
    {
        QMessageBox::information(this, "Успех", "Пароль добавлен");
        clearInputFields();
        loadPasswords();
        emit statusMessage("Пароль для " + service + " добавлен");
    }
    else
    {
        QMessageBox::critical(this, "Ошибка", QString::fromStdString(result.message));
        emit statusMessage("Ошибка добавления пароля");
    }
}

void SmpassWidget::onDeletePassword()
{
    if (selected_service_.isEmpty())
    {
        QMessageBox::warning(this, "Ошибка", "Выберите запись для удаления");
        return;
    }

    auto reply = QMessageBox::question(this, "Подтверждение",
        "Удалить пароль для " + selected_service_ + "?",
        QMessageBox::Yes | QMessageBox::No);

    if (reply == QMessageBox::Yes)
    {
        Asmu::PasswordManager pwd_mgr;
        auto result = pwd_mgr.deletePassword(selected_service_.toStdString());

        if (result.success())
        {
            QMessageBox::information(this, "Успех", "Пароль удалён");
            selected_service_.clear();
            loadPasswords();
            emit statusMessage("Пароль удалён");
        }
        else
        {
            QMessageBox::critical(this, "Ошибка", QString::fromStdString(result.message));
        }
    }
}

void SmpassWidget::onSearchPassword()
{
    QString keyword = search_edit_->text().trimmed();
    if (keyword.isEmpty())
    {
        loadPasswords();
        return;
    }

    password_table_->setRowCount(0);

    Asmu::PasswordManager pwd_mgr;
    auto result = pwd_mgr.searchPasswords(keyword.toStdString());

    if (result.success())
    {
        for (const auto& entry : result.data)
        {
            int row = password_table_->rowCount();
            password_table_->insertRow(row);
            password_table_->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(entry.service)));
            password_table_->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(entry.username)));
            password_table_->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(entry.created_date)));
            password_table_->setItem(row, 3, new QTableWidgetItem(QString::fromStdString(entry.last_modified)));
        }
        emit statusMessage("Найдено записей: " + QString::number(result.data.size()));
    }
}

void SmpassWidget::onRefreshList()
{
    loadPasswords();
}

void SmpassWidget::onHashString()
{
    QString input = hash_input_->text();
    if (input.isEmpty())
    {
        QMessageBox::warning(this, "Ошибка", "Введите строку для хэширования");
        return;
    }

    Asmu::PasswordManager pwd_mgr;
    Asmu::HashAlgorithm algo = (hash_algorithm_->currentText() == "SHA256")
        ? Asmu::HashAlgorithm::SHA256
        : Asmu::HashAlgorithm::AES256;

    auto result = pwd_mgr.hashString(input.toStdString(), algo);

    if (result.success())
    {
        hash_output_->setText(QString::fromStdString(result.data));
        emit statusMessage("Хэширование выполнено: " + hash_algorithm_->currentText());
    }
    else
    {
        QMessageBox::critical(this, "Ошибка", QString::fromStdString(result.message));
    }
}

void SmpassWidget::onEncryptString()
{
    onHashString();
}

void SmpassWidget::onTableItemSelected()
{
    auto selected = password_table_->selectedItems();
    if (!selected.isEmpty())
    {
        int row = selected.first()->row();
        selected_service_ = password_table_->item(row, 0)->text();
        service_edit_->setText(selected_service_);
        username_edit_->setText(password_table_->item(row, 1)->text());
    }
}

void SmpassWidget::onShowPassword()
{
    if (selected_service_.isEmpty())
    {
        QMessageBox::warning(this, "Ошибка", "Выберите запись");
        return;
    }

    Asmu::PasswordManager pwd_mgr;
    auto result = pwd_mgr.getPassword(selected_service_.toStdString());

    if (result.success())
    {
        QMessageBox::information(this, "Пароль",
            "Сервис: " + QString::fromStdString(result.data.service) + "\n" +
            "Пользователь: " + QString::fromStdString(result.data.username) + "\n" +
            "Пароль: " + QString::fromStdString(result.data.password));
    }
    else
    {
        QMessageBox::critical(this, "Ошибка", QString::fromStdString(result.message));
    }
}

void SmpassWidget::clearInputFields()
{
    service_edit_->clear();
    username_edit_->clear();
    password_edit_->clear();
}
