#include "deobf/cli.h"
#include <exception>
#include <iostream>

int wmain(int argc, wchar_t** argv) {
    try {
        return deobf::run_cli(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }
}
