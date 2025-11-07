#include "cmd_options.h"
#include <filesystem>
#include <iostream>
#include <print>
#include <string_view>

namespace CryptoGuard {
namespace po = boost::program_options;

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()("help", "выводит справочное сообщение")(
        "command", po::value<std::string>()->default_value("encrypt"), "команда encrypt, decrypt или checksum")(
        "input,i", po::value<std::string>()->default_value("input.txt"),
        "путь до входного файла")("output,o", po::value<std::string>()->default_value("output.txt"),
                                  "путь до файла, в котором будет сохранён результат")(
        "password,p", po::value<std::string>()->default_value("pass"), "пароль для шифрования и дешифрования");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    try {
        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc_), vm);
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << desc_ << std::endl;
        }

        if (vm.count("command")) {
            auto com = vm["command"].as<std::string>();
            auto it = commandMapping_.find(com);
            if (it == commandMapping_.end()) {
                po::error er("Ошибка: неизвестная команда");
                throw(er);
                return;
            }
            command_ = it->second;
        }

        if (vm.count("input")) {
            inputFile_ = vm["input"].as<std::string>();
            if (std::filesystem::exists(inputFile_)) {
                std::print("Файл существует\n");
            } else {
                po::error er("Входного файла не существует");
                throw(er);
            }
        }
        if (vm.count("output")) {
            outputFile_ = vm["output"].as<std::string>();
            if (outputFile_.empty()) {
                po::error er("Укажите непустое название входного файла");
                throw(er);
            }
        }

        if (vm.count("password")) {
            password_ = vm["password"].as<std::string>();
        }

    } catch (const po::error &e) {
        std::cerr << "Error: " << e.what() << "\n";
        std::cout << desc_ << std::endl;
        throw(e);
        return;
    }
}

}  // namespace CryptoGuard
