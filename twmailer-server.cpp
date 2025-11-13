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
#include <thread>

using namespace std;
namespace fs = std::filesystem;

static volatile sig_atomic_t g_abort = 0;
static void on_sigint(int) { g_abort = 1; }

static bool checkDir(const fs::path &p)
{
    error_code ec;
    if (fs::exists(p, ec))
    {
        return fs::is_directory(p, ec);
    }
    return fs::create_directories(p, ec) || fs::is_directory(p);
}

// Read a line from socket
string readLine(int sock) {
    string line;
    char c;
    ssize_t n;
    while ((n = recv(sock, &c, 1, 0)) > 0) {
        if (c == '\n') break;
        if (c != '\r') line += c;
    }
    return line;
}

// Send a line to socket
void sendLine(int sock, const string& line) {
    string msg = line + "\n";
    send(sock, msg.c_str(), msg.length(), 0);
}

// Validate username (max 8 chars, alphanumeric)
bool isValidUsername(const string& username) {
    if (username.empty() || username.length() > 8) return false;
    return regex_match(username, regex("^[a-z0-9]+$"));
}

// Get user inbox path
fs::path getUserInbox(const string& spool, const string& username) {
    return fs::path(spool) / username;
}

// Get all message files for a user
vector<fs::path> getMessageFiles(const fs::path& inbox) {
    vector<fs::path> files;
    error_code ec;

    if (!fs::exists(inbox, ec) || !fs::is_directory(inbox, ec)) {
        return files;
    }

    for (const auto& entry : fs::directory_iterator(inbox, ec)) {
        if (entry.is_regular_file(ec)) {
            files.push_back(entry.path());
        }
    }

    sort(files.begin(), files.end());
    return files;
}

// Handle SEND command
void handleSend(int sock, const string& spool) {
    string sender = readLine(sock);
    string receiver = readLine(sock);
    string subject = readLine(sock);

    if (!isValidUsername(sender) || !isValidUsername(receiver)) {
        sendLine(sock, "ERR");
        return;
    }

    if (subject.length() > 80) {
        sendLine(sock, "ERR");
        return;
    }

    // Read message body until "."
    string message;
    string line;
    while (true) {
        line = readLine(sock);
        if (line == ".") break;
        message += line + "\n";
    }

    // Create receiver's inbox
    fs::path inbox = getUserInbox(spool, receiver);
    if (!checkDir(inbox)) {
        sendLine(sock, "ERR");
        return;
    }

    // Create unique filename (timestamp-based)
    auto now = chrono::system_clock::now();
    auto timestamp = chrono::duration_cast<chrono::milliseconds>(now.time_since_epoch()).count();
    fs::path msgFile = inbox / (to_string(timestamp) + ".txt");

    // Write message to file
    ofstream out(msgFile);
    if (!out) {
        sendLine(sock, "ERR");
        return;
    }

    out << "Sender: " << sender << "\n";
    out << "Receiver: " << receiver << "\n";
    out << "Subject: " << subject << "\n";
    out << "Message:\n" << message;
    out.close();

    sendLine(sock, "OK");
}

// Handle LIST command
void handleList(int sock, const string& spool) {
    string username = readLine(sock);

    if (!isValidUsername(username)) {
        sendLine(sock, "0");
        return;
    }

    fs::path inbox = getUserInbox(spool, username);
    vector<fs::path> files = getMessageFiles(inbox);

    sendLine(sock, to_string(files.size()));

    for (const auto& file : files) {
        ifstream in(file);
        if (!in) continue;

        string line;
        string subject;

        // Read until we find the subject line
        while (getline(in, line)) {
            if (line.find("Subject: ") == 0) {
                subject = line.substr(9);
                break;
            }
        }

        sendLine(sock, subject.empty() ? "(no subject)" : subject);
    }
}

// Handle READ command
void handleRead(int sock, const string& spool) {
    string username = readLine(sock);
    string msgNumStr = readLine(sock);

    if (!isValidUsername(username)) {
        sendLine(sock, "ERR");
        return;
    }

    int msgNum;
    try {
        msgNum = stoi(msgNumStr);
    } catch (...) {
        sendLine(sock, "ERR");
        return;
    }

    fs::path inbox = getUserInbox(spool, username);
    vector<fs::path> files = getMessageFiles(inbox);

    if (msgNum < 1 || msgNum > (int)files.size()) {
        sendLine(sock, "ERR");
        return;
    }

    ifstream in(files[msgNum - 1]);
    if (!in) {
        sendLine(sock, "ERR");
        return;
    }

    sendLine(sock, "OK");

    string line;
    while (getline(in, line)) {
        sendLine(sock, line);
    }
}

// Handle DEL command
void handleDelete(int sock, const string& spool) {
    string username = readLine(sock);
    string msgNumStr = readLine(sock);

    if (!isValidUsername(username)) {
        sendLine(sock, "ERR");
        return;
    }

    int msgNum;
    try {
        msgNum = stoi(msgNumStr);
    } catch (...) {
        sendLine(sock, "ERR");
        return;
    }

    fs::path inbox = getUserInbox(spool, username);
    vector<fs::path> files = getMessageFiles(inbox);

    if (msgNum < 1 || msgNum > (int)files.size()) {
        sendLine(sock, "ERR");
        return;
    }

    error_code ec;
    if (fs::remove(files[msgNum - 1], ec)) {
        sendLine(sock, "OK");
    } else {
        sendLine(sock, "ERR");
    }
}

static void handleClient(int c, string spool) {
    try {
        while (true) {
            string command = readLine(c);

            if (command.empty()) break;

            transform(command.begin(), command.end(), command.begin(), ::toupper);

            if (command == "SEND") {
                handleSend(c, spool);
            } else if (command == "LIST") {
                handleList(c, spool);
            } else if (command == "READ") {
                handleRead(c, spool);
            } else if (command == "DEL") {
                handleDelete(c, spool);
            } else if (command == "QUIT") {
                break;
            } else {
                sendLine(c, "ERR");
            }
        }
    } catch (...) {
        // Handle any exceptions
    }

    shutdown(c, SHUT_RDWR);
    close(c);
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        cerr << "Usage: " << argv[0] << " <port> <mail-spool-directory>" << endl;
        return 1;
    }
    int port = atoi(argv[1]);
    if (port <= 1024 || port > 65535)
    {
        cerr << "Invalid port, choose between 1025 - 65535" << endl;
        return 1;
    }
    string spool = argv[2];
    if (!checkDir(spool))
    {
        cerr << "Unable to open/create spool directory" << endl;
        return 1;
    }

    std::signal(SIGINT, on_sigint);

    int s = socket(AF_INET, SOCK_STREAM, 0);

    if (s == -1)
    {
        cerr << "Error creating socket" << endl;
        return 1;
    }

    sockaddr_in socket_address{};
    socket_address.sin_port = htons((uint16_t)port);
    socket_address.sin_family = AF_INET;
    socket_address.sin_addr.s_addr = INADDR_ANY;

    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    if (bind(s, (sockaddr *)&socket_address, sizeof(socket_address)) == -1)
    {
        cerr << "Error while binding" << endl;
        close(s);
        return 1;
    }

    if (listen(s, 5) == -1)
    {
        cerr << "Error creating listening socket" << endl;
        close(s);
        return 1;
    }

    cout << "Server listening on 0.0.0.0:" << port << " spool=" << spool << "\n";

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

        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client.sin_addr, clientIP, INET_ADDRSTRLEN);
        cout << "Client connected: " << clientIP << ":" << ntohs(client.sin_port) << endl;

        thread{handleClient, c, spool}.detach();
    }

    cout << "\nShutting down server..." << endl;
    shutdown(s, SHUT_RDWR);
    close(s);
    return 0;
}