//
// Created by Daniel on 20/12/2022.
//

#ifndef QUICHE_BENCHMARKS_BENCHMARK_SERVER_H
#define QUICHE_BENCHMARKS_BENCHMARK_SERVER_H

#include <quiche.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/fcntl.h>

#define LOCAL_CONN_ID_LEN 16
#define MAX_DATAGRAM_SIZE 1350

namespace benchmark {

    class benchmark_server {
    private:
        std::uint16_t server_port;
        int socket_fd;
        uint8_t conn_id[LOCAL_CONN_ID_LEN]{};
        quiche_conn* conn;
        struct addrinfo *local;
        int current_timeout;
    public:
        benchmark_server(std::uint16_t server_port);
        void run();

    };

    benchmark_server::benchmark_server(std::uint16_t server_port) : server_port(server_port), current_timeout(-1) {
        // In the constructor, we retrieve the local address, create a socket_fd and create quiche structure.

        /*
         * UDP RELATED STUFF
         */
        const struct addrinfo hints = {
                .ai_family = PF_UNSPEC,
                .ai_socktype = SOCK_DGRAM,
                .ai_protocol = IPPROTO_UDP
        };


        std::string server_port_string = std::to_string(server_port);
        if (getaddrinfo("127.0.0.1", server_port_string.c_str(), &hints, &local) != 0) {
            std::runtime_error("Could not get address info.");
        }

        socket_fd = socket(local->ai_family, SOCK_DGRAM, 0);
        if (socket_fd < 0) {
            std::runtime_error("Could not create socket_fd.");
        }

        if (fcntl(socket_fd, F_SETFL, O_NONBLOCK) != 0) {
            std::runtime_error("Could not set socket_fd to non-blocking.");
        }

        if (bind(socket_fd, local->ai_addr, local->ai_addrlen) < 0) {
            std::runtime_error("Could not bind socket_fd.");
        }

        int opt = 1;
        if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            std::runtime_error("Could not set socket_fd to reusable.");
        }

        /*
         * QUICHE RELATED STUFF
         */
        quiche_config* config = quiche_config_new(QUICHE_PROTOCOL_VERSION);
        if (config == nullptr) {
            std::runtime_error("Could not create quiche config.");
        }

        quiche_config_load_cert_chain_from_pem_file(config, "./cert.crt");
        quiche_config_load_priv_key_from_pem_file(config, "./cert.key");

        quiche_config_set_application_protos(config,
                                             (uint8_t *) "\x0ahq-interop\x05hq-29\x05hq-28\x05hq-27\x08http/0.9", 38);

        quiche_config_set_max_idle_timeout(config, 5000);
        quiche_config_set_max_recv_udp_payload_size(config, MAX_DATAGRAM_SIZE);
        quiche_config_set_max_send_udp_payload_size(config, MAX_DATAGRAM_SIZE);
        quiche_config_set_initial_max_data(config, 10000000);
        quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000);
        quiche_config_set_initial_max_stream_data_bidi_remote(config, 1000000);
        quiche_config_set_initial_max_streams_bidi(config, 100);
        quiche_config_set_cc_algorithm(config, QUICHE_CC_RENO);
    }

    void benchmark_server::run() {

    }

} // benchmark

#endif //QUICHE_BENCHMARKS_BENCHMARK_SERVER_H
