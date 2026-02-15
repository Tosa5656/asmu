/**
 * @file logger.cpp
 * @brief Реализация потокобезопасного логгера
 * @author Tosa5656
 * @date 4 января, 2026
 */
#include "logger.h"

Logger* Logger::instance_ = nullptr;
std::mutex Logger::mutex_;