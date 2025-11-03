#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <string>
#include <vector>

using namespace std;
namespace fs = std::filesystem;

static volatile sig_atomic_t g_abort = 0;
static void on_sigint(int) { g_abort = 1; }

static bool checkDir(const fs::path &p)
{
    error_code ec;
    if (fs::exists(p, ec))
    {
        // wenn dir existiert
        return fs::is_directory(p, ec);
    }
    // legt alle fehlenden Zwischenordner an
    return fs::create_directories(p, ec) || fs::is_directory(p);
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        cerr << "Please enter like: " << argv[0] << " <port> <mail-spool-directory>";
        return 1;
    }
    int port = atoi(argv[1]);
    if (port <= 1024 || port > 65535)
    {
        cerr << "Invalid port, choose between 1025 - 65535";
        return 1;
    }
    string spool = argv[2];
    if (!checkDir(spool))
    {
        cerr << "Unable to open/create spool directory" << endl;
        return 1;
    }

    // wenn user strg+c eingibt, bricht programm ab
    std::signal(SIGINT, on_sigint);

    int s = socket(AF_INET, SOCK_STREAM, 0); // legt neuen socket an(ipv4,steam socket, tcp)

    if (s == -1)
    {
        cerr << "Error creating socket" << endl;
        return 1;
    }

    sockaddr_in socket_address{};
    socket_address.sin_port = htons((uint16_t)port);
    socket_address.sin_family = AF_INET;         // ipv4
    socket_address.sin_addr.s_addr = INADDR_ANY; // server hört auf alle schnittstellen (0.0.0.0)

    // bindet socket an port
    if (bind(s, (sockaddr *)&socket_address, sizeof(socket_address)) == -1)
    {
        cerr << "error while binding" << endl;
        return 1;
    }

    if (listen(s, 5) == -1)
    {
        cerr << "error creating listening socket" << endl;
        return 1;
    }

    std::cout << "listening on 0.0.0.0:" << port << " spool=" << spool << "\n";

    // Warten auf eingehende verbindungen
    while (!g_abort)
    {
        sockaddr_in client{};
        socklen_t len = sizeof(client);
        int c = accept(s, (sockaddr *)&client, &len);

        if (c == -1)
        {
            if (errno == EINTR && g_abort)
            {
                break;
            }
            perror("accept");
            continue;
        }
        shutdown(c, SHUT_RDWR);
        close(c);
    }
    shutdown(s, SHUT_RDWR);
    close(s);
    return 0;
}