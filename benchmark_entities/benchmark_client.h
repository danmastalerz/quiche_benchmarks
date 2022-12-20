//
// Created by Daniel on 20/12/2022.
//

#ifndef QUICHE_BENCHMARKS_BENCHMARK_CLIENT_H
#define QUICHE_BENCHMARKS_BENCHMARK_CLIENT_H

#include <quiche.h>

#define LOCAL_CONN_ID_LEN 16

namespace benchmark {

    class benchmark_client {
    private:
        std::uint16_t server_port;
        int socket;
        uint8_t conn_id[LOCAL_CONN_ID_LEN]{};
        quiche_conn* conn;

        void send_out_quic_packets();
    public:
        benchmark_client(std::uint16_t server_port);
        void run();
    };

    /*
     * Creates an instance of the benchmark client class. Do not start any networking stuff here.
     */
    benchmark_client::benchmark_client(std::uint16_t server_port) : server_port(server_port) {

    }

    /*
     * Starts the actual benchmark. Firstly, client will try to connect to the server. Then, it will start to receive
     * data from the server. Every one second, it prints out the actual throughput of the connection.
     */
    void benchmark_client::run() {

    }

} // benchmark

#endif //QUICHE_BENCHMARKS_BENCHMARK_CLIENT_H
