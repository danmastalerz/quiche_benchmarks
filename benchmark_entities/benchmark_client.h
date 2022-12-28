//
// Created by Daniel on 20/12/2022.
//

#ifndef QUICHE_BENCHMARKS_BENCHMARK_CLIENT_H
#define QUICHE_BENCHMARKS_BENCHMARK_CLIENT_H

#include <quiche.h>
#include <vector>
#include <sys/poll.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/fcntl.h>
#include <csignal>
#include <cstring>

#define DEBUG false

#define LOCAL_CONN_ID_LEN 16
#define MAX_DATAGRAM_SIZE 65000
#define MAX_UDP_DATAGRAM_SIZE 65000
#define MAX_TOKEN_LEN \
    sizeof("quiche") - 1 + \
    sizeof(struct sockaddr_storage) + \
    QUICHE_MAX_CONN_ID_LEN

namespace benchmark {

    class benchmark_client {
    private:
        int socket_fd;
        quiche_conn* conn{};
        quiche_config* config{};
        struct addrinfo *peer_addr{};
        struct sockaddr_storage local{};
        socklen_t local_addr_len{};
        uint8_t cid[LOCAL_CONN_ID_LEN]{};
        int current_timeout;
        std::vector<uint8_t> recv_buf;
        ssize_t recv_len;
        std::vector<uint8_t> send_buf;
        struct pollfd poll_register{};
        size_t received_bytes;

        bool wait_for_events();
        void process_packet();
        void send_out_packets();
        static uint8_t *gen_cid(uint8_t *c_id, size_t cid_len);
        void print_current_speed() const;
    public:
        explicit benchmark_client(std::uint16_t server_port);
        [[noreturn]] void run();
    };

    /*
     * Creates an instance of the benchmark client class. Do not start any networking stuff here.
     */
    benchmark_client::benchmark_client(std::uint16_t server_port) :
    current_timeout(-1),
    recv_len(0),
    recv_buf(MAX_UDP_DATAGRAM_SIZE),
    send_buf(MAX_UDP_DATAGRAM_SIZE),
    local_addr_len(sizeof(sockaddr_storage)),
    received_bytes(0) {
        /*
         * UDP RELATED STUFF
         */
        const struct addrinfo hints = {
                .ai_family = PF_UNSPEC,
                .ai_socktype = SOCK_DGRAM,
                .ai_protocol = IPPROTO_UDP
        };


        std::string server_port_string = std::to_string(server_port);
        if (getaddrinfo("127.0.0.1", server_port_string.c_str(), &hints, &peer_addr) != 0) {
            throw std::runtime_error("Could not get address info.");
        }

        socket_fd = socket(peer_addr->ai_family, SOCK_DGRAM, 0);
        if (socket_fd < 0) {
            throw std::runtime_error("Could not create socket_fd.");
        }

        if (fcntl(socket_fd, F_SETFL, O_NONBLOCK) != 0) {
            throw std::runtime_error("Could not set socket_fd to non-blocking.");
        }

        if (getsockname(socket_fd, (struct sockaddr *) &local,&local_addr_len) != 0) {
            throw std::runtime_error("Could not get socket_fd name.");
        }

        // Create pollfd structure
        poll_register = {
                .fd = socket_fd,
                .events = POLLIN
        };

        /*
        * QUICHE RELATED STUFF
        */
        config = quiche_config_new(0xbabababa);
        if (config == nullptr) {
            throw std::runtime_error("Could not create quiche config.");
        }

        quiche_config_set_application_protos(config,
                                             (uint8_t *) "\x0ahq-interop\x05hq-29\x05hq-28\x05hq-27\x08http/0.9", 38);

        quiche_config_set_max_idle_timeout(config, 5000);
        quiche_config_set_max_recv_udp_payload_size(config, MAX_DATAGRAM_SIZE);
        quiche_config_set_max_send_udp_payload_size(config, MAX_DATAGRAM_SIZE);
        quiche_config_set_initial_max_data(config, 10000000);
        quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000);
        quiche_config_set_initial_max_stream_data_bidi_remote(config, 1000000);
        quiche_config_set_initial_max_stream_data_uni(config, 1000000);
        quiche_config_set_initial_max_streams_bidi(config, 1000);
        quiche_config_set_initial_max_streams_uni(config, 1000);
        quiche_config_set_disable_active_migration(config, true);
        quiche_config_set_cc_algorithm(config, QUICHE_CC_RENO);
        quiche_config_set_max_stream_window(config, MAX_DATAGRAM_SIZE);
        quiche_config_set_max_connection_window(config, MAX_DATAGRAM_SIZE);
    }

    /*
     * Starts the actual benchmark. Firstly, client will try to connect to the server. Then, it will start to receive
     * data from the server. Every one second, it prints out the actual throughput of the connection.
     */
    void benchmark_client::run() {
        // Generating connection id.
        uint8_t* scid = gen_cid(cid, LOCAL_CONN_ID_LEN);

        // Connect to the server.
        conn = quiche_connect("127.0.0.1", scid, LOCAL_CONN_ID_LEN, (struct sockaddr *) &local,
                local_addr_len,peer_addr->ai_addr, peer_addr->ai_addrlen, config);

        if (conn == nullptr) {
            throw std::runtime_error("Could not create quiche connection.");
        }

        // Send the first packet.
        send_out_packets();

        // Run quiche loop
        while(true) {
            if (wait_for_events()) {
                process_packet();
            } else {
                // Timeout - handle it.
                quiche_conn_on_timeout(conn);
                send_out_packets();
            }

            // Print current goodput
            print_current_speed();

            // Send out outgoing packets.
            send_out_packets();
        }
    }

    bool benchmark_client::wait_for_events() {
        if (DEBUG) std::cout << "Waiting for event.\n";

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
        // Here, opposite to the server, we receive many packets, instead of just one.
        // TODO: investigate what's up with that
        while(true) {
            sockaddr_storage peer{};
            socklen_t peer_len = sizeof(sockaddr_storage);
            memset(&peer, 0, peer_len);

            recv_len = recvfrom(socket_fd, recv_buf.data(), recv_buf.size(), 0,
                                (struct sockaddr *) &peer, &peer_len);
            if (DEBUG) std::cout << "Received " << recv_len << " bytes." << std::endl;
            if (recv_len < 0) {
                if (DEBUG) std::cout << "Warning: recv_len = " << recv_len <<  " < 0\n";
                break;
            }

            // Feed received UDP data into quiche.
            quiche_recv_info recv_info = {
                    (struct sockaddr *) &peer,
                    peer_len,
                    (struct sockaddr *) &local,
                    local_addr_len
            };
            ssize_t done = quiche_conn_recv(conn, recv_buf.data(), recv_len, &recv_info);
            if (done < 0) {
                throw std::runtime_error("Couldn't process QUIC packets.");
            }
        }
        if (DEBUG) std::cout << "Read some data without timeout.\n";
        return true;
    }

    void benchmark_client::send_out_packets() {
        if (DEBUG) std::cout << "In send_out_packets\n";
        quiche_send_info send_info;

        // While there is something to send - then send.
        while(true) {
            ssize_t written = quiche_conn_send(conn, send_buf.data(), send_buf.size(), &send_info);

            if (written == QUICHE_ERR_DONE) {
                break;
            }

            if (written < 0) {
                throw std::runtime_error("Could not create packet to send.");
            }

            ssize_t sent = sendto(socket_fd, send_buf.data(), written, 0, (struct sockaddr *) &send_info.to, send_info.to_len);
            if (DEBUG) std::cout << "Sent " << sent << " bytes." << std::endl;
            if (sent != written) {
                throw std::runtime_error("Could not send packet.");
            }
        }

        current_timeout = (int) quiche_conn_timeout_as_millis(conn);
        if (DEBUG) std::cout << "Finished sending out packets.\n";
    }

    uint8_t *benchmark_client::gen_cid(uint8_t *c_id, size_t cid_len) {
        int rng = open("/dev/urandom", O_RDONLY);
        if (rng < 0) {
            throw std::runtime_error("Could not open /dev/urandom.");
        }

        ssize_t rand_len = read(rng, c_id, cid_len);
        if (rand_len < 0) {
            throw std::runtime_error("Could not create connection id.");
        }

        return c_id;
    }

    void benchmark_client::process_packet() {
        // Check if connection is closed now.
        if (quiche_conn_is_closed(conn)) {
            if (DEBUG) std::cout << "Connection closed.\n";
            exit(0);
        }

        // If connection is establised, then we can read the data.
        if (quiche_conn_is_established(conn)) {
            // Iterate through readable streams.
            uint64_t s = 0;
            bool fin = false;
            quiche_stream_iter *readable = quiche_conn_readable(conn);
            while(quiche_stream_iter_next(readable, &s)) {
                auto received_from_stream = quiche_conn_stream_recv(conn, s, recv_buf.data(), recv_buf.size(), &fin);
                if (received_from_stream < 0) {
                    throw std::runtime_error("Could not receive data from the stream.");
                }
                received_bytes += received_from_stream;
            }
        }
    }

    void benchmark_client::print_current_speed() const {
        double received_in_megabytes = (double) received_bytes / (1000.0 * 1000.0);
        std::cout << "Received megabytes: " << received_in_megabytes << "MB\n";
    }

} // benchmark

#endif //QUICHE_BENCHMARKS_BENCHMARK_CLIENT_H
