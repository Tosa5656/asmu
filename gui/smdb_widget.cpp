/**
 * @file smdb_widget.cpp
 * @brief Реализация виджета smdb
 * @author Tosa5656
 * @date 1 марта, 2026
 */
#include "smdb_widget.h"
#include "../api/include/asmu.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QHeaderView>

SmdbWidget::SmdbWidget(QWidget* parent)
    : QWidget(parent)
    , search_group_(nullptr)
    , search_edit_(nullptr)
    , search_button_(nullptr)
    , list_button_(nullptr)
    , attacks_table_(nullptr)
    , details_group_(nullptr)
    , show_info_button_(nullptr)
    , show_tools_button_(nullptr)
    , clear_button_(nullptr)
    , details_text_(nullptr)
{
    setupUi();
    onListAttacks();
}

SmdbWidget::~SmdbWidget()
{
}

void SmdbWidget::setupUi()
{
    QVBoxLayout* main_layout = new QVBoxLayout(this);

    search_group_ = new QGroupBox("Поиск атак MITRE ATT&CK", this);
    QHBoxLayout* search_layout = new QHBoxLayout(search_group_);

    search_edit_ = new QLineEdit(this);
    search_edit_->setPlaceholderText("Введите ключевое слово (например: brute force, phishing)...");
    search_button_ = new QPushButton("Искать", this);
    list_button_ = new QPushButton("Показать все", this);
    connect(search_button_, &QPushButton::clicked, this, &SmdbWidget::onSearchAttacks);
    connect(list_button_, &QPushButton::clicked, this, &SmdbWidget::onListAttacks);

    search_layout->addWidget(search_edit_);
    search_layout->addWidget(search_button_);
    search_layout->addWidget(list_button_);

    main_layout->addWidget(search_group_);

    attacks_table_ = new QTableWidget(this);
    attacks_table_->setColumnCount(3);
    attacks_table_->setHorizontalHeaderLabels({"ID", "Название", "Тактика"});
    attacks_table_->horizontalHeader()->setStretchLastSection(true);
    attacks_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    attacks_table_->setSelectionMode(QAbstractItemView::SingleSelection);
    attacks_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    connect(attacks_table_, &QTableWidget::itemSelectionChanged, this, &SmdbWidget::onTableItemSelected);
    main_layout->addWidget(attacks_table_);

    details_group_ = new QGroupBox("Детали атаки", this);
    QVBoxLayout* details_layout = new QVBoxLayout(details_group_);

    QHBoxLayout* details_buttons_layout = new QHBoxLayout();
    show_info_button_ = new QPushButton("Показать информацию", this);
    show_tools_button_ = new QPushButton("Инструменты защиты", this);
    clear_button_ = new QPushButton("Очистить", this);
    connect(show_info_button_, &QPushButton::clicked, this, &SmdbWidget::onShowAttackInfo);
    connect(show_tools_button_, &QPushButton::clicked, this, &SmdbWidget::onShowTools);
    connect(clear_button_, &QPushButton::clicked, this, &SmdbWidget::onClearOutput);

    details_buttons_layout->addWidget(show_info_button_);
    details_buttons_layout->addWidget(show_tools_button_);
    details_buttons_layout->addWidget(clear_button_);
    details_buttons_layout->addStretch();
    details_layout->addLayout(details_buttons_layout);

    details_text_ = new QTextEdit(this);
    details_text_->setReadOnly(true);
    details_layout->addWidget(details_text_);

    main_layout->addWidget(details_group_);
}

void SmdbWidget::onListAttacks()
{
    attacks_table_->setRowCount(0);
    details_text_->clear();
    emit statusMessage("Загрузка списка атак...");

    Asmu::AttackDatabase attack_db;
    auto result = attack_db.listAllAttacks();

    if (result.success())
    {
        for (const auto& attack_id : result.data)
        {
            auto info_result = attack_db.getAttackInfo(attack_id);
            if (info_result.success())
            {
                int row = attacks_table_->rowCount();
                attacks_table_->insertRow(row);
                attacks_table_->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(info_result.data.id)));
                attacks_table_->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(info_result.data.title)));
                attacks_table_->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(info_result.data.tactic)));
            }
        }
        emit statusMessage("Загружено атак: " + QString::number(result.data.size()));
    }
    else
    {
        QMessageBox::critical(this, "Ошибка", QString::fromStdString(result.message));
        emit statusMessage("Ошибка загрузки атак");
    }
}

void SmdbWidget::onSearchAttacks()
{
    QString keyword = search_edit_->text().trimmed();
    if (keyword.isEmpty())
    {
        onListAttacks();
        return;
    }

    attacks_table_->setRowCount(0);
    details_text_->clear();
    emit statusMessage("Поиск атак: " + keyword + "...");

    Asmu::AttackDatabase attack_db;
    auto result = attack_db.searchAttacks(keyword.toStdString());

    if (result.success())
    {
        for (const auto& search_result : result.data)
        {
            auto info_result = attack_db.getAttackInfo(search_result.attack_id);
            if (info_result.success())
            {
                int row = attacks_table_->rowCount();
                attacks_table_->insertRow(row);
                attacks_table_->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(info_result.data.id)));
                attacks_table_->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(info_result.data.title)));
                attacks_table_->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(info_result.data.tactic)));
            }
        }
        emit statusMessage("Найдено атак: " + QString::number(result.data.size()));
    }
    else
    {
        QMessageBox::critical(this, "Ошибка", QString::fromStdString(result.message));
        emit statusMessage("Ошибка поиска");
    }
}

void SmdbWidget::onShowAttackInfo()
{
    if (selected_attack_id_.isEmpty())
    {
        QMessageBox::warning(this, "Ошибка", "Выберите атаку из списка");
        return;
    }

    details_text_->clear();
    emit statusMessage("Загрузка информации об атаке " + selected_attack_id_ + "...");

    Asmu::AttackDatabase attack_db;
    auto result = attack_db.getAttackInfo(selected_attack_id_.toStdString());

    if (result.success())
    {
        QString output = "=== " + QString::fromStdString(result.data.title) + " ===\n\n";
        output += "ID: " + QString::fromStdString(result.data.id) + "\n";
        output += "Тактика: " + QString::fromStdString(result.data.tactic) + "\n";
        output += "Платформа: " + QString::fromStdString(result.data.platform) + "\n\n";
        output += "Описание:\n" + QString::fromStdString(result.data.description) + "\n\n";

        if (!result.data.recommendations.empty())
        {
            output += "Меры защиты:\n";
            for (const auto& rec : result.data.recommendations)
            {
                output += "  ✓ " + QString::fromStdString(rec) + "\n";
            }
            output += "\n";
        }

        if (!result.data.protection_tools.empty())
        {
            output += "Инструменты ASMU:\n";
            for (const auto& tool : result.data.protection_tools)
            {
                output += "  🔧 " + QString::fromStdString(tool) + "\n";
            }
        }

        details_text_->setText(output);
        emit statusMessage("Информация загружена: " + selected_attack_id_);
    }
    else
    {
        QMessageBox::critical(this, "Ошибка", QString::fromStdString(result.message));
        emit statusMessage("Ошибка загрузки информации");
    }
}

void SmdbWidget::onShowTools()
{
    if (selected_attack_id_.isEmpty())
    {
        QMessageBox::warning(this, "Ошибка", "Выберите атаку из списка");
        return;
    }

    details_text_->clear();
    emit statusMessage("Загрузка инструментов защиты для " + selected_attack_id_ + "...");

    Asmu::AttackDatabase attack_db;
    auto result = attack_db.getProtectionGuidance(selected_attack_id_.toStdString());

    if (result.success())
    {
        QString output = "=== Рекомендации по защите ===\n\n";
        output += "Уровень риска: " + QString::fromStdString(result.data.risk_level) + "\n\n";

        if (!result.data.detection_methods.empty())
        {
            output += "Методы обнаружения:\n";
            for (const auto& method : result.data.detection_methods)
            {
                output += "  • " + QString::fromStdString(method) + "\n";
            }
            output += "\n";
        }

        if (!result.data.prevention_steps.empty())
        {
            output += "Шаги предотвращения:\n";
            for (const auto& step : result.data.prevention_steps)
            {
                output += "  ✓ " + QString::fromStdString(step) + "\n";
            }
            output += "\n";
        }

        if (!result.data.response_actions.empty())
        {
            output += "Действия при обнаружении:\n";
            for (const auto& action : result.data.response_actions)
            {
                output += "  ⚡ " + QString::fromStdString(action) + "\n";
            }
            output += "\n";
        }

        if (!result.data.sm_tools_command.empty())
        {
            output += "Команды ASMU:\n";
            output += "  " + QString::fromStdString(result.data.sm_tools_command) + "\n";
        }

        details_text_->setText(output);
        emit statusMessage("Рекомендации загружены");
    }
    else
    {
        QMessageBox::critical(this, "Ошибка", QString::fromStdString(result.message));
        emit statusMessage("Ошибка загрузки инструментов");
    }
}

void SmdbWidget::onTableItemSelected()
{
    auto selected = attacks_table_->selectedItems();
    if (!selected.isEmpty())
    {
        int row = selected.first()->row();
        selected_attack_id_ = attacks_table_->item(row, 0)->text();
    }
}

void SmdbWidget::onClearOutput()
{
    details_text_->clear();
    emit statusMessage("Вывод очищен");
}
