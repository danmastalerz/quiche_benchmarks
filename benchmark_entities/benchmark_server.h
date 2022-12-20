//
// Created by Daniel on 20/12/2022.
//

#ifndef QUICHE_BENCHMARKS_BENCHMARK_SERVER_H
#define QUICHE_BENCHMARKS_BENCHMARK_SERVER_H

#include <quiche.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/fcntl.h>
#include <vector>
#include <sys/poll.h>

#define LOCAL_CONN_ID_LEN 16
#define MAX_DATAGRAM_SIZE 1350
#define MAX_UDP_DATAGRAM_SIZE 65535

namespace benchmark {

    class benchmark_server {
    private:
        std::uint16_t server_port;
        int socket_fd;
        uint8_t conn_id[LOCAL_CONN_ID_LEN]{};
        quiche_conn* conn;
        struct addrinfo *local{};
        struct sockaddr_storage peer_addr{};
        socklen_t peer_addr_len{};
        int current_timeout;
        std::vector<char> recv_buf;
        ssize_t recv_len;
        std::vector<char> send_buf;
        struct pollfd poll_register;
        size_t received_bytes;

        bool wait_for_event();
        void process_packet();
        void send_out_packets();
        void print_current_speed();
    public:
        benchmark_server(std::uint16_t server_port);

        [[noreturn]] void run();

    };

    benchmark_server::benchmark_server(std::uint16_t server_port) :
    server_port(server_port),
    current_timeout(-1),
    recv_buf(MAX_UDP_DATAGRAM_SIZE),
    send_buf(MAX_UDP_DATAGRAM_SIZE),
    peer_addr_len(sizeof(struct sockaddr_storage)),
    recv_len(0),
    received_bytes(0) {
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
            throw std::runtime_error("Could not get address info.");
        }

        socket_fd = socket(local->ai_family, SOCK_DGRAM, 0);
        if (socket_fd < 0) {
            throw std::runtime_error("Could not create socket_fd.");
        }


        if (fcntl(socket_fd, F_SETFL, O_NONBLOCK) != 0) {
            throw std::runtime_error("Could not set socket_fd to non-blocking.");
        }

        if (bind(socket_fd, local->ai_addr, local->ai_addrlen) < 0) {
            throw std::runtime_error("Could not bind socket_fd.");
        }

        int opt = 1;
        if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            throw std::runtime_error("Could not set socket_fd to reusable.");
        }

        // Create pollfd structure
        poll_register = {
                .fd = socket_fd,
                .events = POLLIN
        };

        /*
         * QUICHE RELATED STUFF
         */
        quiche_config* config = quiche_config_new(QUICHE_PROTOCOL_VERSION);
        if (config == nullptr) {
            throw std::runtime_error("Could not create quiche config.");
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
    /*
     * MAIN BENCHMARK LOOP
     * IT DOES AS FOLLOWS:
     * 1. POLL THE UDP SOCKET ON INCOMING PACKETS, WAIT UP TO THE MOMENT OF TIMEOUT GIVEN BY QUICHE
     *    OR DONT WAIT IF NOT SPECIFIED
     * 2. PROCESS THE INCOMING PACKETS WITH QUICHE, CONTINUE ACCORDING TO WHETHER CONNECTION IS ESTABLISHED OR NOT
     * 3. PRINT CURRENT SPEED
     * 4. SEND OUTGOING PACKETS
     */
    [[noreturn]] void benchmark_server::run() {
        while(true) {
            // If we received a packet without a timeout, we process it.
            if (wait_for_event()) {
                process_packet();
            }
            // Inform about the throughput
            print_current_speed();
            // Send out outgoing packets.
            send_out_packets();
        }

    }

    /*
     * POLL ON THE INCOMING UDP PACKETS
     * RETURN TRUE IF ANY EVENT HAPPENED
     * RETURN FALSE IF THERE WAS A TIMEOUT
     */
    bool benchmark_server::wait_for_event() {

        // Waiting for any action
        int poll_result = poll(&poll_register, 1, current_timeout);

        // Checking for any errors.
        if (poll_result < 0) {
            throw std::runtime_error("Polling error.");
        }

        // Checking if there was a timeout.
        if (poll_result == 0) {
            return false;
        }

        // Now we handle the situation as if there was no timeout.
        // So - we need to receive incoming packet.
        // TODO: Use functions to receive many packets at once.
        recv_len = recvfrom(socket_fd, recv_buf.data(), recv_buf.size(), 0,
                            (struct sockaddr *) &peer_addr, &peer_addr_len);

        // It's more of a sanity check - it shouldn't happen.
        if (recv_len < 0) {
            throw std::runtime_error("Could not receive packet.");
        }
        received_bytes += recv_len;
        return true;
    }

    void benchmark_server::send_out_packets() {

    }

    void benchmark_server::print_current_speed() {
    }

    void benchmark_server::process_packet() {

    }

} // benchmark

#endif //QUICHE_BENCHMARKS_BENCHMARK_SERVER_H
