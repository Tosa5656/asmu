/**
 * @file mainwindow.h
 * @brief Главное окно графического интерфейса ASMU
 * @author Tosa5656
 * @date 1 марта, 2026
 */
#pragma once

#include <QMainWindow>
#include <QTabWidget>
#include <QStatusBar>
#include <QMenuBar>
#include <QAction>
#include <QLabel>

class SmpassWidget;
class SmnetWidget;
class SmlogWidget;
class SmsshWidget;
class SmdbWidget;

/**
 * @brief Главное окно приложения ASMU GUI
 *
 * Предоставляет единый интерфейс для доступа ко всем утилитам ASMU
 * через вкладки. Каждая вкладка содержит виджет соответствующей утилиты.
 */
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    /**
     * @brief Конструктор главного окна
     * @param parent Родительский виджет
     */
    explicit MainWindow(QWidget* parent = nullptr);

    /**
     * @brief Деструктор
     */
    ~MainWindow();

private slots:
    /**
     * @brief Показать диалог "О программе"
     */
    void showAboutDialog();

    /**
     * @brief Показать справку
     */
    void showHelp();

    /**
     * @brief Обновить статус-бар
     * @param message Сообщение для отображения
     */
    void updateStatusBar(const QString& message);

private:
    /**
     * @brief Инициализировать UI компоненты
     */
    void setupUi();

    /**
     * @brief Создать меню
     */
    void createMenus();

    /**
     * @brief Создать вкладки утилит
     */
    void createTabs();

    QTabWidget* tab_widget_;        ///< Виджет вкладок
    QStatusBar* status_bar_;        ///< Статус-бар
    QLabel* status_label_;          ///< Метка статуса

    SmpassWidget* smpass_widget_;   ///< Виджет smpass
    SmnetWidget* smnet_widget_;     ///< Виджет smnet
    SmlogWidget* smlog_widget_;     ///< Виджет smlog
    SmsshWidget* smssh_widget_;     ///< Виджет smssh
    SmdbWidget* smdb_widget_;       ///< Виджет smdb

    QMenu* file_menu_;              ///< Меню "Файл"
    QMenu* help_menu_;              ///< Меню "Справка"

    QAction* exit_action_;          ///< Действие "Выход"
    QAction* about_action_;         ///< Действие "О программе"
    QAction* help_action_;          ///< Действие "Справка"
};
