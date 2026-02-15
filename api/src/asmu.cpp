/**
 * @file asmu.cpp
 * @brief Реализация ASMU API
 * @author Tosa5656
 * @date 4 января, 2026
 */

#include "asmu.h"
#include <iostream>

// Флаг инициализации
static bool g_initialized = false;

namespace Asmu
{
    /**
    * @brief Инициализация ASMU API
    * @return Удача/Неудача
    */
    bool initialize()
    {
        if (g_initialized)
            return true;

        g_initialized = true;
        return true;
    }

    /**
    * @brief Очистка ASMU API
    */
    void cleanup()
    {
        if (!g_initialized)
            return;

        g_initialized = false;
    }

    /**
    * @brief Получить версию ASMU API
    * @return Версия
    */
    const char* getVersion()
    {
        return VERSION;
    }

    /**
    * @brief Получить описание ASMU API
    * @return Описание
    */
    const char* getDescription()
    {
        return DESCRIPTION;
    }

    /**
    * @brief Получить последнюю ошибку
    * @return Сообщение об ошибке
    */
    std::string getLastError()
    {
        return "No error information available";
    }
}
