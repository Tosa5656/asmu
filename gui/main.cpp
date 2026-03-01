/**
 * @file main.cpp
 * @brief Точка входа для графического интерфейса ASMU
 * @author Tosa5656
 * @date 1 марта, 2026
 */
#include "mainwindow.h"
#include "../api/include/asmu.h"

#include <QApplication>
#include <QMessageBox>
#include <QStyleFactory>

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);

    app.setApplicationName("ASMU GUI");
    app.setApplicationVersion("1.0.0");
    app.setOrganizationName("ASMU");

    app.setStyle(QStyleFactory::create("Fusion"));

    if (!Asmu::initialize())
    {
        QMessageBox::critical(nullptr, "Ошибка инициализации",
            "Не удалось инициализировать ASMU API.\n" +
            QString::fromStdString(Asmu::getLastError()));
        return 1;
    }

    MainWindow window;
    window.show();

    int result = app.exec();

    Asmu::cleanup();

    return result;
}
