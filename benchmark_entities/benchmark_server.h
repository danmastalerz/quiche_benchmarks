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
#include <cstring>
#include <csignal>

#define LOCAL_CONN_ID_LEN 16
#define MAX_DATAGRAM_SIZE 1350
#define MAX_UDP_DATAGRAM_SIZE 65535
#define MAX_TOKEN_LEN \
    sizeof("quiche") - 1 + \
    sizeof(struct sockaddr_storage) + \
    QUICHE_MAX_CONN_ID_LEN

namespace benchmark {

    class benchmark_server {
    private:
        std::uint16_t server_port;
        int socket_fd;
        uint8_t conn_id[LOCAL_CONN_ID_LEN]{};
        quiche_conn* conn{};
        quiche_config* config{};
        struct addrinfo *local{};
        struct sockaddr_storage peer_addr{};
        socklen_t peer_addr_len{};
        uint8_t cid[LOCAL_CONN_ID_LEN]{};
        int current_timeout;
        std::vector<uint8_t> recv_buf;
        ssize_t recv_len;
        std::vector<uint8_t> send_buf;
        struct pollfd poll_register;
        size_t received_bytes;
        bool connection_created;

        bool wait_for_event();
        bool process_packet();
        void send_out_packets();
        void print_current_speed();
        void mint_token(const uint8_t *dcid, size_t dcid_len,
                        struct sockaddr_storage *addr, socklen_t addr_len,
                        uint8_t *token, size_t *token_len);
        bool validate_token(const uint8_t *token, size_t token_len,
                            struct sockaddr_storage *addr, socklen_t addr_len,
                            uint8_t *odcid, size_t *odcid_len);
        uint8_t *gen_cid(uint8_t *cid, size_t cid_len);
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
            received_bytes(0),
            connection_created(false) {
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
        config = quiche_config_new(QUICHE_PROTOCOL_VERSION);
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
                if (!process_packet()) {
                    continue;
                }
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
        // Convert to megabytes
        double received_in_megabytes = (double) received_bytes / (1000.0 * 1000.0);
        std::cout << "Throughput: " << received_in_megabytes << "\n";
        //clear the console
        std::cout << "\033[2J\033[1;1H";

    }

    // Return false if the caller should continue to the next iteration of the loop.
    // Return true otherwise.
    bool benchmark_server::process_packet() {
        /*
         * CONNECTION ID AND TOKEN STUFF
         */
        uint8_t type;
        uint32_t version;

        uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
        size_t scid_len = sizeof(scid);

        uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
        size_t dcid_len = sizeof(dcid);

        uint8_t odcid[QUICHE_MAX_CONN_ID_LEN];
        size_t odcid_len = sizeof(odcid);

        uint8_t token[MAX_TOKEN_LEN];
        size_t token_len = sizeof(token);

        // Parsing the header.
        int parsing_header_result = quiche_header_info(recv_buf.data(), recv_len, LOCAL_CONN_ID_LEN,
                                                       &version, &type, scid, &scid_len, dcid, &dcid_len,token,
                                                       &token_len);
        // Check if successful.
        if (parsing_header_result < 0) {
            throw std::runtime_error("Could not parse header.");
        }

        // If there was no previous communication then accept the connection.
        if (!connection_created) {
            /*
             * CREATING NEW CONNECTION STUFF
             */

            // Version negotiation
            if (!quiche_version_is_supported(version)) {
                ssize_t written = quiche_negotiate_version(scid, scid_len, dcid, dcid_len, send_buf.data(), send_buf.size());

                if (written < 0) {
                    throw std::runtime_error("Could not write version negotiation packet.");
                }

                // We immediately send this packet.
                ssize_t sent = sendto(socket_fd, send_buf.data(), written, 0,
                                      (struct sockaddr *) &peer_addr, peer_addr_len);

                if (sent != written) {
                    throw std::runtime_error("Could not send version negotiation packet.");
                }
                return false;
            }

            // Handling the token
            // TODO: Learn what actually is going on there :)
            // TODO: Document the functions used here.
            if (token_len == 0) {
                mint_token(dcid, dcid_len, &peer_addr, peer_addr_len, token, &token_len);
                uint8_t new_connection_id[LOCAL_CONN_ID_LEN];
                if (gen_cid(new_connection_id, LOCAL_CONN_ID_LEN) == nullptr) {
                    throw std::runtime_error("Could not generate connection ID.");
                }

                ssize_t written = quiche_retry(scid, scid_len, dcid, dcid_len, new_connection_id, LOCAL_CONN_ID_LEN,
                                               token, token_len, version, send_buf.data(), send_buf.size());
                if (written < 0) {
                    throw std::runtime_error("Could not write retry packet.");
                }

                ssize_t sent = sendto(socket_fd, send_buf.data(), written, 0,
                                      (struct sockaddr *) &peer_addr, peer_addr_len);
                if (sent != written) {
                    throw std::runtime_error("Could not send retry packet.");
                }
                return false;
            }

            // Handle invalid token
            if (!validate_token(token, token_len, &peer_addr, peer_addr_len, odcid, &odcid_len)) {
                throw std::runtime_error("Invalid token.");
            }

            // Now we can create the connection.
            conn = quiche_accept(cid, LOCAL_CONN_ID_LEN, odcid, odcid_len, local->ai_addr, local->ai_addrlen,
                                 (struct sockaddr *) &peer_addr, peer_addr_len, config);

            if (conn == nullptr) {
                throw std::runtime_error("Couldn't create connection");
            }
            connection_created = true;

            return true;
        } else {

        }
    }

    void benchmark_server::mint_token(const uint8_t *dcid, size_t dcid_len, struct sockaddr_storage *addr,
                                      socklen_t addr_len, uint8_t *token, size_t *token_len) {
        memcpy(token, "quiche", sizeof("quiche") - 1);
        memcpy(token + sizeof("quiche") - 1, addr, addr_len);
        memcpy(token + sizeof("quiche") - 1 + addr_len, dcid, dcid_len);

        *token_len = sizeof("quiche") - 1 + addr_len + dcid_len;
    }

    bool benchmark_server::validate_token(const uint8_t *token, size_t token_len, struct sockaddr_storage *addr,
                                          socklen_t addr_len, uint8_t *odcid, size_t *odcid_len) {
        if ((token_len < sizeof("quiche") - 1) ||
            memcmp(token, "quiche", sizeof("quiche") - 1)) {
            return false;
        }

        token += sizeof("quiche") - 1;
        token_len -= sizeof("quiche") - 1;

        if ((token_len < addr_len) || memcmp(token, addr, addr_len)) {
            return false;
        }

        token += addr_len;
        token_len -= addr_len;

        if (*odcid_len < token_len) {
            return false;
        }

        memcpy(odcid, token, token_len);
        *odcid_len = token_len;

        return true;
    }

    uint8_t *benchmark_server::gen_cid(uint8_t *cid, size_t cid_len) {
        int rng = open("/dev/urandom", O_RDONLY);
        if (rng < 0) {
            throw std::runtime_error("Could not open /dev/urandom.");
        }

        ssize_t rand_len = read(rng, cid, cid_len);
        if (rand_len < 0) {
            throw std::runtime_error("Could not create connection id.");
        }

        return cid;
    }

} // benchmark

#endif //QUICHE_BENCHMARKS_BENCHMARK_SERVER_H
