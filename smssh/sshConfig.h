/**
 * @file sshConfig.h
 * @brief Управление конфигурацией SSH и анализ безопасности
 * @author Tosa5656
 * @date 4 января, 2026
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <iostream>
#include <sstream>
#include <filesystem>
#include <algorithm>

namespace fs = std::filesystem;

/**
 * @brief Структура, представляющая рекомендацию по безопасности SSH
 */
struct SSHSecurityRecommendation {
    std::string key;               ///< Ключ конфигурации SSH
    std::string current_value;     ///< Текущее значение в конфигурации
    std::string recommended_value; ///< Рекомендуемое безопасное значение
    std::string description;       ///< Описание проблемы безопасности
    std::string severity;          ///< Уровень серьезности: "critical", "high", "medium", "low"
    bool is_set;                   ///< Настроен ли этот параметр в данный момент
};

/**
 * @brief Класс управления конфигурацией SSH
 *
 * Загрузка, анализ и усиление безопасности конфигурации SSH-сервера.
 */
class SSHConfig {
public:
    /**
     * @brief Конструктор по умолчанию — путь к стандартному конфигу
     */
    SSHConfig();

    /**
     * @brief Конструктор с путём к конфигу
     * @param configPath Путь к файлу конфигурации SSH
     */
    SSHConfig(const std::string& configPath);

    /**
     * @brief Загрузить конфигурацию из файла
     * @return true при успешной загрузке
     */
    bool loadConfig();

    /**
     * @brief Сохранить конфигурацию в файл
     * @param outputPath Путь для сохранения (необязательно)
     * @return true при успешной записи
     */
    bool saveConfig(const std::string& outputPath = "");

    /**
     * @brief Получить текущие настройки SSH
     * @return Карта «параметр — значение»
     */
    std::map<std::string, std::string> getCurrentSettings() const;

    /**
     * @brief Проанализировать конфигурацию на проблемы безопасности
     * @return Вектор рекомендаций
     */
    std::vector<SSHSecurityRecommendation> analyzeSecurity();

    /**
     * @brief Сгенерировать безопасную конфигурацию SSH
     * @return Строка с конфигурацией
     */
    std::string generateSecureConfig();
    
    bool setSetting(const std::string& key, const std::string& value);
    std::string getSetting(const std::string& key) const;
    
    bool hasSetting(const std::string& key) const;
    void removeSetting(const std::string& key);
    
    std::string getConfigPath() const { return config_path_; }
    std::string getLastError() const { return last_error_; }
    
private:
    std::string config_path_;
    std::string last_error_;
    std::map<std::string, std::string> settings_;
    std::vector<std::string> original_lines_;
    
    void parseConfig();
    std::vector<std::string> readLines(const std::string& path);
    bool writeLines(const std::string& path, const std::vector<std::string>& lines);
    
    // Рекомендации по безопасности
    std::vector<SSHSecurityRecommendation> getRecommendations() const;
    std::map<std::string, std::string> getSecureDefaults() const;
    
    // Вспомогательные функции
    std::string trim(const std::string& str);
    bool isComment(const std::string& line);
    std::pair<std::string, std::string> parseLine(const std::string& line);
};
