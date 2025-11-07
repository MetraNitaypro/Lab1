#include "cmd_options.h"
#include <gtest/gtest.h>

TEST(ProgramOptions, parse1) {
    char *argv[] = {"prog",       "--input", "input.txt", "--output", "out.txt",
                    "--password", "12345",   "--command", "encrypt"};
    int argc = 9;

    CryptoGuard::ProgramOptions pr;
    try {
        pr.Parse(argc, argv);
        SUCCEED() << "Условие выполнено";
    } catch (const std::exception &e) {
        FAIL() << "Условие не выполнено";
    }
}

TEST(ProgramOptions, parse2) {

    char *argv[] = {"prog", "-i", "input.txt", "--output", "out.txt", "--password", "12345", "--command", "decrypt"};
    int argc = 9;

    CryptoGuard::ProgramOptions pr;
    try {
        pr.Parse(argc, argv);
        SUCCEED() << "Условие выполнено";
    } catch (const std::exception &e) {
        FAIL() << "Условие не выполнено";
    }
}

TEST(ProgramOptions, parse3) {

    char *argv[] = {"prog",       "--input", "input.txt", "--output", "out.txt",
                    "--password", "12345",   "--command", "encrrypt"};
    int argc = 9;

    CryptoGuard::ProgramOptions pr;
    try {
        pr.Parse(argc, argv);
        FAIL() << "Условие не выполнено";
    } catch (const std::exception &e) {
        SUCCEED() << "Условие выполнено";
    }
}

TEST(ProgramOptions, parse4) {

    char *argv[] = {"prog",       "--input", "input.txt", "--output", "out.txt",
                    "--password", "12345",   "--command", "enccrypt", "--help"};
    int argc = 9;

    CryptoGuard::ProgramOptions pr;
    try {
        pr.Parse(argc, argv);
        FAIL() << "Условие не выполнено";
    } catch (const std::exception &e) {
        SUCCEED() << "Условие выполнено";
    }
}

TEST(ProgramOptions, parse5) {

    char *argv[] = {"prog", "--input", "in.txt", "--output", "out.txt", "--command", "encrypt"};
    int argc = 7;

    CryptoGuard::ProgramOptions pr;
    try {
        pr.Parse(argc, argv);
        FAIL() << "Условие не выполнено";
    } catch (const std::exception &e) {
        SUCCEED() << "Условие выполнено";
    }
}
TEST(ProgramOptions, parse6) {

    char *argv[] = {"prog", "--help"};
    int argc = 2;

    CryptoGuard::ProgramOptions pr;
    try {
        pr.Parse(argc, argv);
        SUCCEED() << "Условие выполнено";
    } catch (const std::exception &e) {
        FAIL() << "Условие не выполнено";
    }
}