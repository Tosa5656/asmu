#ifndef ASMU_H
#define ASMU_H

/**
 * @file asmu.h
 * @brief ASMU C++ API - API для использования функций ASMU
 * @author Tosa5656
 * @date 4 января, 2026
 */

#include "smpass_api.h"
#include "smnet_api.h"
#include "smlog_api.h"
#include "smssh_api.h"
#include "smdb_api.h"

namespace Asmu
{
    // Информация и версии API и его описании
    constexpr const char* VERSION = "1.0.0";
    constexpr const char* DESCRIPTION = "ASMU C++ API";

    // Инициализация, очистка, получение основной информации
    bool initialize();
    void cleanup();
    const char* getVersion();
    const char* getDescription();
    std::string getLastError();
}

#endif
