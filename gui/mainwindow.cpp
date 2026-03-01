/**
 * @file mainwindow.cpp
 * @brief Реализация главного окна ASMU GUI
 * @author Tosa5656
 * @date 1 марта, 2026
 */
#include "mainwindow.h"
#include "smpass_widget.h"
#include "smnet_widget.h"
#include "smlog_widget.h"
#include "smssh_widget.h"
#include "smdb_widget.h"

#include <QVBoxLayout>
#include <QMessageBox>
#include <QApplication>

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , tab_widget_(nullptr)
    , status_bar_(nullptr)
    , status_label_(nullptr)
    , smpass_widget_(nullptr)
    , smnet_widget_(nullptr)
    , smlog_widget_(nullptr)
    , smssh_widget_(nullptr)
    , smdb_widget_(nullptr)
    , file_menu_(nullptr)
    , help_menu_(nullptr)
    , exit_action_(nullptr)
    , about_action_(nullptr)
    , help_action_(nullptr)
{
    setupUi();
    createMenus();
    createTabs();

    setWindowTitle("ASMU - Advanced Security Manager Utils");
    resize(1200, 800);

    updateStatusBar("Готов к работе");
}

MainWindow::~MainWindow()
{
}

void MainWindow::setupUi()
{
    tab_widget_ = new QTabWidget(this);
    tab_widget_->setTabPosition(QTabWidget::North);
    setCentralWidget(tab_widget_);

    status_bar_ = statusBar();
    status_label_ = new QLabel(this);
    status_bar_->addPermanentWidget(status_label_);
}

void MainWindow::createMenus()
{
    file_menu_ = menuBar()->addMenu("&Файл");

    exit_action_ = new QAction("&Выход", this);
    exit_action_->setShortcut(QKeySequence::Quit);
    connect(exit_action_, &QAction::triggered, this, &QMainWindow::close);
    file_menu_->addAction(exit_action_);

    help_menu_ = menuBar()->addMenu("&Справка");

    help_action_ = new QAction("&Помощь", this);
    help_action_->setShortcut(QKeySequence::HelpContents);
    connect(help_action_, &QAction::triggered, this, &MainWindow::showHelp);
    help_menu_->addAction(help_action_);

    about_action_ = new QAction("&О программе", this);
    connect(about_action_, &QAction::triggered, this, &MainWindow::showAboutDialog);
    help_menu_->addAction(about_action_);
}

void MainWindow::createTabs()
{
    smpass_widget_ = new SmpassWidget(this);
    connect(smpass_widget_, &SmpassWidget::statusMessage, this, &MainWindow::updateStatusBar);
    tab_widget_->addTab(smpass_widget_, "🔐 Пароли (smpass)");

    smnet_widget_ = new SmnetWidget(this);
    connect(smnet_widget_, &SmnetWidget::statusMessage, this, &MainWindow::updateStatusBar);
    tab_widget_->addTab(smnet_widget_, "🌐 Сеть (smnet)");

    smlog_widget_ = new SmlogWidget(this);
    connect(smlog_widget_, &SmlogWidget::statusMessage, this, &MainWindow::updateStatusBar);
    tab_widget_->addTab(smlog_widget_, "📋 Логи (smlog)");

    smssh_widget_ = new SmsshWidget(this);
    connect(smssh_widget_, &SmsshWidget::statusMessage, this, &MainWindow::updateStatusBar);
    tab_widget_->addTab(smssh_widget_, "🔒 SSH (smssh)");

    smdb_widget_ = new SmdbWidget(this);
    connect(smdb_widget_, &SmdbWidget::statusMessage, this, &MainWindow::updateStatusBar);
    tab_widget_->addTab(smdb_widget_, "📚 База атак (smdb)");
}

void MainWindow::showAboutDialog()
{
    QMessageBox::about(this, "О программе ASMU",
        "<h2>ASMU - Advanced Security Manager Utils</h2>"
        "<p>Версия 1.0.0</p>"
        "<p>Набор утилит для администраторов Linux: мониторинг, анализ и усиление безопасности.</p>"
        "<p><b>Утилиты:</b></p>"
        "<ul>"
        "<li><b>smpass</b> - Хранение паролей с AES256</li>"
        "<li><b>smnet</b> - Мониторинг сети и портов</li>"
        "<li><b>smlog</b> - Анализ системных логов</li>"
        "<li><b>smssh</b> - Безопасность SSH</li>"
        "<li><b>smdb</b> - База атак MITRE ATT&CK</li>"
        "</ul>"
        "<p>Лицензия: GPL v3</p>"
        "<p>Автор: Tosa5656</p>"
    );
}

void MainWindow::showHelp()
{
    QMessageBox::information(this, "Справка ASMU",
        "<h3>Использование ASMU GUI</h3>"
        "<p>Выберите вкладку нужной утилиты для работы:</p>"
        "<ul>"
        "<li><b>Пароли</b> - управление паролями и шифрование</li>"
        "<li><b>Сеть</b> - сканирование портов и мониторинг соединений</li>"
        "<li><b>Логи</b> - чтение и анализ системных логов</li>"
        "<li><b>SSH</b> - проверка конфигурации и мониторинг атак</li>"
        "<li><b>База атак</b> - справочник MITRE ATT&CK</li>"
        "</ul>"
        "<p>Для подробной информации используйте кнопки 'Справка' на каждой вкладке.</p>"
    );
}

void MainWindow::updateStatusBar(const QString& message)
{
    status_label_->setText(message);
    status_bar_->showMessage(message, 5000);
}
