#include "cmd_options.h"
#include <filesystem>
#include <iostream>
#include <print>
#include <string_view>

namespace CryptoGuard {
namespace po = boost::program_options;
ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()("help", "выводит справочное сообщение")(
        "command", po::value<std::string>(), "команда encrypt, decrypt или checksum")("input", po::value<std::string>(),
                                                                                      "путь до входного файла")(
        "output", po::value<std::string>(), "путь до файла, в котором будет сохранён результат")(
        "password", po::value<std::string>(), "пароль для шифрования и дешифрования");

    const char **argv;
    int argc = 0;
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
            std::cout << "Ошибка: неизвестная команд" << std::endl;
        }
        command_ = it->second;
    }

    if (vm.count("input")) {
        inputFile_ = vm["input"].as<std::string>();
    }

    if (vm.count("output")) {
        outputFile_ = vm["output"].as<std::string>();
    }

    if (vm.count("password")) {
        password_ = vm["password"].as<std::string>();
    }
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {

    if () {
    }

    std::string path = "test.txt";

    if (std::filesystem::exists(inputFile_)) {
        std::cout << "Файл существует\n";
    } else {
        std::cout << "Файл НЕ существует\n";
    }
}

}  // namespace CryptoGuard
