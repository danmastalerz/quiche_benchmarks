#include <iostream>
#include "./benchmark_entities/benchmark_server.h"

#define SERVER_DEFAULT_PORT 1234

int main(int argc, char *argv[]) {
    std::uint16_t server_port = argc > 1 ? std::stoi(argv[1]) : SERVER_DEFAULT_PORT;
    benchmark::benchmark_server server(server_port);
    server.run();
}
