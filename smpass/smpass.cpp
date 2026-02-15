/**
 * @file smpass.cpp
 * @brief Утилита командной строки для хранения паролей (ASMU)
 * @author Tosa5656
 * @date 4 января, 2026
 */

#include "../logger/logger.h"
#include "storage.h"
#include "sha256.h"
#include "aes256.h"
#include <openssl/rand.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <vector>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <filesystem>

Storage storage;  ///< Глобальное хранилище паролей

namespace fs = std::filesystem;

// Формат вывода шифрования: сырой файл, изображение (BMP) или аудио (WAV)
enum class EncryptFormat { Asmu, Image, Audio };

/**
 * @brief Прочитать файл в байты
 */
static std::vector<unsigned char> read_file_to_bytes(const std::string& path)
{
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open())
        return {};
    auto size = f.tellg();
    f.seekg(0);
    std::vector<unsigned char> data(size);
    if (!f.read(reinterpret_cast<char*>(data.data()), size))
        return {};
    return data;
}

/**
 * @brief Записать байты в файл
 */
static bool write_bytes_to_file(const std::string& path, const std::vector<unsigned char>& data)
{
    std::ofstream f(path, std::ios::binary);
    if (!f.is_open())
        return false;
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
    return f.good();
}

/**
 * @brief Заполнить буфер случайными байтами (OpenSSL)
 */
static void fill_random(std::vector<unsigned char>& buf)
{
    if (!buf.empty() && RAND_bytes(buf.data(), static_cast<int>(buf.size())) != 1)
    {
        for (size_t i = 0; i < buf.size(); ++i)
            buf[i] = static_cast<unsigned char>(rand() % 256);
    }
}

// --- Встраивание в изображение (BMP 24-bit) ---
// Данные прячутся в пикселях: сначала 4 байта длины (LE), затем payload. Остальное — шум.

static bool write_bmp_with_payload(const std::string& path, const std::vector<unsigned char>& payload)
{
    const uint32_t len = static_cast<uint32_t>(payload.size());
    std::vector<unsigned char> raw;
    raw.push_back(static_cast<unsigned char>(len & 0xFF));
    raw.push_back(static_cast<unsigned char>((len >> 8) & 0xFF));
    raw.push_back(static_cast<unsigned char>((len >> 16) & 0xFF));
    raw.push_back(static_cast<unsigned char>((len >> 24) & 0xFF));
    raw.insert(raw.end(), payload.begin(), payload.end());

    const size_t payload_len = raw.size();
    size_t w = std::max<size_t>(1, static_cast<size_t>(std::ceil(std::sqrt((payload_len + 2) / 3.0))));
    size_t h = std::max<size_t>(1, (payload_len + w * 3 - 1) / (w * 3));
    size_t row_size = (w * 3 + 3) & ~3u;
    size_t pixel_bytes = row_size * h;

    raw.resize(pixel_bytes);
    if (pixel_bytes > payload_len)
    {
        std::vector<unsigned char> tail(raw.begin() + payload_len, raw.end());
        fill_random(tail);
        std::copy(tail.begin(), tail.end(), raw.begin() + payload_len);
    }

    const uint32_t image_size = static_cast<uint32_t>(row_size * h);
    const uint32_t file_size = 54 + image_size;

    std::ofstream out(path, std::ios::binary);
    if (!out.is_open())
        return false;

    unsigned char header[54] = { 'B', 'M' };
    *reinterpret_cast<uint32_t*>(header + 2) = file_size;
    *reinterpret_cast<uint32_t*>(header + 10) = 54;
    *reinterpret_cast<uint32_t*>(header + 14) = 40;
    *reinterpret_cast<int32_t*>(header + 18) = static_cast<int32_t>(w);
    *reinterpret_cast<int32_t*>(header + 22) = static_cast<int32_t>(h);
    *reinterpret_cast<uint16_t*>(header + 26) = 1;
    *reinterpret_cast<uint16_t*>(header + 28) = 24;
    *reinterpret_cast<uint32_t*>(header + 34) = static_cast<uint32_t>(image_size);

    out.write(reinterpret_cast<const char*>(header), 54);
    for (int64_t y = static_cast<int64_t>(h) - 1; y >= 0; --y)
    {
        size_t off = static_cast<size_t>(y) * row_size;
        out.write(reinterpret_cast<const char*>(raw.data() + off), row_size);
    }
    return out.good();
}

static std::vector<unsigned char> read_bmp_payload(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open())
        return {};
    char header[54];
    if (!f.read(header, 54) || header[0] != 'B' || header[1] != 'M')
        return {};
    int32_t w = *reinterpret_cast<int32_t*>(header + 18);
    int32_t h = *reinterpret_cast<int32_t*>(header + 22);
    if (w <= 0 || h <= 0 || w > 50000 || h > 50000)
        return {};
    size_t row_size = (static_cast<size_t>(w) * 3 + 3) & ~3u;
    size_t total = row_size * static_cast<size_t>(h);
    std::vector<unsigned char> pixels(total);
    for (int y = h - 1; y >= 0; --y)
    {
        if (!f.read(reinterpret_cast<char*>(pixels.data() + static_cast<size_t>(y) * row_size), row_size))
            return {};
    }
    if (pixels.size() < 4)
        return {};
    uint32_t len = static_cast<uint32_t>(pixels[0]) | (static_cast<uint32_t>(pixels[1]) << 8) |
                   (static_cast<uint32_t>(pixels[2]) << 16) | (static_cast<uint32_t>(pixels[3]) << 24);
    if (len == 0 || len > pixels.size() - 4)
        return {};
    return std::vector<unsigned char>(pixels.begin() + 4, pixels.begin() + 4 + len);
}

// --- Встраивание в аудио (WAV 16-bit mono, 44100 Hz) ---
// Сначала 4 байта длины (LE), затем payload в сэмплах. Остальное — шум, при воспроизведении звучит как шум.

static const uint32_t WAV_SAMPLE_RATE = 44100u;

static bool write_wav_with_payload(const std::string& path, const std::vector<unsigned char>& payload)
{
    const uint32_t len = static_cast<uint32_t>(payload.size());
    uint32_t total_samples = std::max(WAV_SAMPLE_RATE * 2u, (len + 4 + 1) / 2u);
    uint32_t data_size = total_samples * 2u;
    uint32_t file_size = 36 + data_size;

    std::ofstream out(path, std::ios::binary);
    if (!out.is_open())
        return false;

    unsigned char riff[12] = { 'R', 'I', 'F', 'F', 0, 0, 0, 0, 'W', 'A', 'V', 'E' };
    *reinterpret_cast<uint32_t*>(riff + 4) = file_size;
    out.write(reinterpret_cast<const char*>(riff), 12);

    unsigned char fmt[24] = { 'f', 'm', 't', ' ', 16, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 16, 0 };
    *reinterpret_cast<uint32_t*>(fmt + 8) = WAV_SAMPLE_RATE;
    *reinterpret_cast<uint32_t*>(fmt + 12) = WAV_SAMPLE_RATE * 2u;
    out.write(reinterpret_cast<const char*>(fmt), 24);

    unsigned char data_hdr[8] = { 'd', 'a', 't', 'a', 0, 0, 0, 0 };
    *reinterpret_cast<uint32_t*>(data_hdr + 4) = data_size;
    out.write(reinterpret_cast<const char*>(data_hdr), 8);

    std::vector<int16_t> samples(total_samples);
    size_t idx = 0;
    samples[idx++] = static_cast<int16_t>(len & 0xFFFF);
    samples[idx++] = static_cast<int16_t>((len >> 16) & 0xFFFF);
    for (size_t j = 0; j < payload.size(); j += 2)
    {
        int16_t s = static_cast<unsigned char>(payload[j]);
        if (j + 1 < payload.size())
            s |= static_cast<int16_t>(static_cast<unsigned char>(payload[j + 1]) << 8);
        samples[idx++] = s;
    }
    while (idx < total_samples)
    {
        std::vector<unsigned char> r(2);
        fill_random(r);
        samples[idx++] = static_cast<int16_t>(r[0] | (r[1] << 8));
    }

    out.write(reinterpret_cast<const char*>(samples.data()), total_samples * 2);
    return out.good();
}

static std::vector<unsigned char> read_wav_payload(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open())
        return {};
    char riff[12];
    if (!f.read(riff, 12) || riff[0] != 'R' || riff[1] != 'I' || riff[2] != 'F' || riff[3] != 'F')
        return {};
    if (riff[8] != 'W' || riff[9] != 'A' || riff[10] != 'V' || riff[11] != 'E')
        return {};
    while (f.read(riff, 8))
    {
        uint32_t chunk_size = *reinterpret_cast<uint32_t*>(riff + 4);
        if (riff[0] == 'd' && riff[1] == 'a' && riff[2] == 't' && riff[3] == 'a')
        {
            if (chunk_size < 4)
                return {};
            std::vector<char> raw(chunk_size);
            if (!f.read(raw.data(), chunk_size))
                return {};
            uint32_t len = static_cast<unsigned char>(raw[0]) | (static_cast<unsigned char>(raw[1]) << 8) |
                           (static_cast<unsigned char>(raw[2]) << 16) | (static_cast<unsigned char>(raw[3]) << 24);
            if (len == 0 || len > chunk_size - 4)
                return {};
            std::vector<unsigned char> out(len);
            for (uint32_t i = 0; i < len; ++i)
                out[i] = static_cast<unsigned char>(raw[4 + i]);
            return out;
        }
        f.seekg(chunk_size, std::ios::cur);
    }
    return {};
}

/**
 * @brief Зашифровать файл (изображение, аудио и т.д.)
 * Создаёт файл с зашифрованными данными и отдельный файл с ключом (.key).
 * Формат: asmu — сырой файл; image — BMP с «спрятанными» данными; audio — WAV с шумом.
 */
static void encrypt_file(const std::string& input_path, const std::string& output_path, EncryptFormat format)
{
    if (!fs::exists(input_path))
    {
        std::cerr << "[ERROR] Файл не найден: " << input_path << std::endl;
        return;
    }

    auto data = read_file_to_bytes(input_path);
    if (data.empty())
    {
        std::cerr << "[ERROR] Не удалось прочитать файл или файл пуст: " << input_path << std::endl;
        return;
    }

    std::string out;
    if (format == EncryptFormat::Image)
        out = output_path.empty() ? input_path + ".bmp" : output_path;
    else if (format == EncryptFormat::Audio)
        out = output_path.empty() ? input_path + ".wav" : output_path;
    else
        out = output_path.empty() ? input_path + ".asmu" : output_path;

    std::string key_path = out + ".key";

    try
    {
        auto key = AES256::generateKey();
        auto iv = AES256::generateIV();
        auto encrypted = AES256::encryptBytes(data, key, iv);

        bool ok = false;
        if (format == EncryptFormat::Image)
            ok = write_bmp_with_payload(out, encrypted);
        else if (format == EncryptFormat::Audio)
            ok = write_wav_with_payload(out, encrypted);
        else
            ok = write_bytes_to_file(out, encrypted);

        if (!ok)
        {
            std::cerr << "[ERROR] Не удалось записать зашифрованный файл: " << out << std::endl;
            return;
        }

        std::ofstream kf(key_path);
        if (!kf.is_open())
        {
            std::cerr << "[ERROR] Не удалось создать файл ключа: " << key_path << std::endl;
            return;
        }
        kf << AES256::keyToHex(key);
        kf.close();

        std::cout << "[INFO] Файл зашифрован: " << out << std::endl;
        if (format == EncryptFormat::Image)
            std::cout << "[INFO] Данные спрятаны в изображении (BMP)." << std::endl;
        else if (format == EncryptFormat::Audio)
            std::cout << "[INFO] Данные спрятаны в аудио (WAV, при воспроизведении — шум)." << std::endl;
        std::cout << "[INFO] Ключ сохранён: " << key_path << " (храните в надёжном месте)" << std::endl;
    }
    catch (const std::exception& e)
    {
        std::cerr << "[ERROR] Ошибка шифрования: " << e.what() << std::endl;
    }
}

/**
 * @brief Расшифровать файл
 * Ключ читается из файла <зашифрованный_файл>.key
 * Поддерживаются: сырой .asmu, изображение .bmp, аудио .wav
 */
static void decrypt_file(const std::string& encrypted_path, const std::string& output_path)
{
    if (!fs::exists(encrypted_path))
    {
        std::cerr << "[ERROR] Файл не найден: " << encrypted_path << std::endl;
        return;
    }

    std::string key_path = encrypted_path + ".key";
    if (!fs::exists(key_path))
    {
        std::cerr << "[ERROR] Файл ключа не найден: " << key_path << std::endl;
        return;
    }

    std::vector<unsigned char> data;
    if (encrypted_path.size() >= 4 && encrypted_path.compare(encrypted_path.size() - 4, 4, ".bmp") == 0)
        data = read_bmp_payload(encrypted_path);
    else if (encrypted_path.size() >= 4 && encrypted_path.compare(encrypted_path.size() - 4, 4, ".wav") == 0)
        data = read_wav_payload(encrypted_path);
    else
        data = read_file_to_bytes(encrypted_path);

    if (data.empty())
    {
        std::cerr << "[ERROR] Не удалось прочитать зашифрованный файл: " << encrypted_path << std::endl;
        return;
    }

    std::string key_hex;
    {
        std::ifstream kf(key_path);
        if (!kf.is_open())
        {
            std::cerr << "[ERROR] Не удалось открыть файл ключа: " << key_path << std::endl;
            return;
        }
        std::getline(kf, key_hex);
    }

    std::string out = output_path;
    if (out.empty())
    {
        out = encrypted_path;
        if (out.size() >= 5 && out.compare(out.size() - 5, 5, ".asmu") == 0)
            out.resize(out.size() - 5);
        else if (out.size() >= 4 && out.compare(out.size() - 4, 4, ".bmp") == 0)
        {
            out.resize(out.size() - 4);
            out += ".decrypted";
        }
        else if (out.size() >= 4 && out.compare(out.size() - 4, 4, ".wav") == 0)
        {
            out.resize(out.size() - 4);
            out += ".decrypted";
        }
        else
            out += ".decrypted";
    }

    try
    {
        auto key = AES256::hexToKey(key_hex);
        auto decrypted = AES256::decryptBytes(data, key);

        if (!write_bytes_to_file(out, decrypted))
        {
            std::cerr << "[ERROR] Не удалось записать файл: " << out << std::endl;
            return;
        }

        std::cout << "[INFO] Файл расшифрован: " << out << std::endl;
    }
    catch (const std::exception& e)
    {
        std::cerr << "[ERROR] Ошибка расшифровки: " << e.what() << std::endl;
    }
}

/**
 * @brief Показать справку по командам
 */
void help()
{
    std::cout << "Использование smpass:" << std::endl;
    std::cout << "smpass help - показать справочное сообщение" << std::endl;
    std::cout << "smpass add-password - добавить новый пароль" << std::endl;
    std::cout << "smpass delete-password - удалить пароль" << std::endl;
    std::cout << "smpass hash-sha256 <строка> - хэшировать строку с SHA256" << std::endl;
    std::cout << "smpass hash-aes256 <строка> - зашифровать строку с AES256" << std::endl;
    std::cout << "smpass encrypt-file <входной> [выходной] [asmu|image|audio] - зашифровать файл" << std::endl;
    std::cout << "  asmu  — сырой файл .asmu (по умолчанию)" << std::endl;
    std::cout << "  image — спрятать в изображение .bmp (выглядит как картинка с шумом)" << std::endl;
    std::cout << "  audio — спрятать в аудио .wav (при воспроизведении звучит как шум)" << std::endl;
    std::cout << "smpass decrypt-file <файл.asmu|.bmp|.wav> [выходной] - расшифровать (ключ из <файл>.key)" << std::endl;
}

// Запрашивает у пользователя детали пароля и добавляет его
/**
 * @brief Интерактивно добавить новый пароль
 */
void add_password()
{
    std::string name, login, password, message;

    std::cout << "Введите имя для пароля: ";
    std::cin >> name;

    std::cout << "Введите логин для пароля: ";
    std::cin >> login;

    std::cout << "Введите пароль: ";
    std::cin >> password;

    std::cout << "Введите информацию для пароля: ";
    std::cin >> message;

    storage.addNewPassword(name, login, password, message);
}

/**
 * @brief Интерактивно удалить пароль по имени
 */
void delete_password()
{
    std::string name;
    std::cout << "Введите имя: ";
    std::cin >> name;
    storage.deletePassword(name);
}

/**
 * @brief Вычислить хэш SHA256 от строки
 * @param string Строка для хэширования
 */
void hash_sha256(std::string string)
{
    std::stringstream ss;
    ss << "Хэш (SHA256): " << SHA256::hashString(string);
    LogInfo(ss.str());
}

/**
 * @brief Зашифровать строку AES256
 * @param string Строка для шифрования
 */
void hash_aes256(std::string string)
{
    auto key = AES256::generateKey();
    auto iv = AES256::generateIV();

    std::string encryptedString = AES256::encrypt(string, key, iv);
    std::string str_key = AES256::keyToHex(key);

    std::stringstream ss;
    ss << "Зашифрованная строка: " << encryptedString;
    LogInfo(ss.str());
    ss.str("");
    ss << "Ключ шифрования: " << str_key;
    LogInfo(ss.str());
}

/**
 * @brief Точка входа утилиты smpass
 * @param argc Количество аргументов
 * @param argv Аргументы командной строки
 * @return 0 — успех, 1 — ошибка
 */
int main(int argc, char* argv[])
{
    if (argc == 1) {
        std::cout << "Выполните smpass help для справки." << std::endl;
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "help") == 0) {
        help();
        return 0;
    }

    // Добавить новый пароль
    if (argc >= 2 && strcmp(argv[1], "add-password") == 0) {
        add_password();
        return 0;
    }

    // Удалить пароль
    if (argc >= 2 && strcmp(argv[1], "delete-password") == 0) {
        delete_password();
        return 0;
    }

    // Хэшировать с SHA256
    if (argc == 3 && strcmp(argv[1], "hash-sha256") == 0) {
        hash_sha256(argv[2]);
        return 0;
    }

    // Шифровать с AES256
    if (argc == 3 && strcmp(argv[1], "hash-aes256") == 0) {
        hash_aes256(argv[2]);
        return 0;
    }

    // Зашифровать файл (сырой .asmu, изображение .bmp или аудио .wav)
    if (argc >= 3 && strcmp(argv[1], "encrypt-file") == 0) {
        std::string out = (argc >= 4) ? argv[3] : "";
        EncryptFormat fmt = EncryptFormat::Asmu;
        if (argc >= 5) {
            if (strcmp(argv[4], "image") == 0) fmt = EncryptFormat::Image;
            else if (strcmp(argv[4], "audio") == 0) fmt = EncryptFormat::Audio;
        } else if (!out.empty()) {
            if (out.size() >= 4 && out.compare(out.size() - 4, 4, ".bmp") == 0) fmt = EncryptFormat::Image;
            else if (out.size() >= 4 && out.compare(out.size() - 4, 4, ".wav") == 0) fmt = EncryptFormat::Audio;
        }
        encrypt_file(argv[2], out, fmt);
        return 0;
    }

    // Расшифровать файл
    if (argc >= 3 && strcmp(argv[1], "decrypt-file") == 0) {
        std::string out = (argc >= 4) ? argv[3] : "";
        decrypt_file(argv[2], out);
        return 0;
    }

    std::stringstream ss;
    ss << "Неизвестная команда: " << argv[1];
    LogError(ss.str());
    LogError("Доступные команды: smpass help");
    return 1;
}