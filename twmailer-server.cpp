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
#include <mutex>
#include <chrono>
#include <unordered_map>
#include <ldap.h>

using namespace std;
namespace fs = std::filesystem;

static volatile sig_atomic_t g_abort = 0;
static void on_sigint(int) { g_abort = 1; }

std::mutex spoolMutex;
std::mutex blacklistMutex;

struct Session
{
    bool authenticated = false;
    std::string username;
};
struct LoginInfo
{
    int failedAttempts = 0;
    std::chrono::system_clock::time_point blacklistUntil{};
};

std::unordered_map<std::string, LoginInfo> LOGIN_MAP;
std::string SPOOL_DIR;

static bool checkDir(const fs::path &p)
{
    error_code ec;
    if (fs::exists(p, ec))
    {
        return fs::is_directory(p, ec);
    }
    return fs::create_directories(p, ec) || fs::is_directory(p);
}

// blacklist file
fs::path getBlacklistFile()
{
    return fs::path(SPOOL_DIR) / "blacklist.txt";
}

void loadBlackList()

{
    std::lock_guard<std::mutex> lock(blacklistMutex);

    LOGIN_MAP.clear();
    fs::path file = getBlacklistFile();
    std::ifstream in(file);
    if (!in)
        return;

    auto now = std::chrono::system_clock::now();
    std::string ip;
    int fails;
    long long until;

    while (true)
    {
        if (!(in >> ip))
            break;
        if (!(in >> fails))
            break;
        if (!(in >> until))
            break;

        LoginInfo info;
        info.blacklistUntil = std::chrono::system_clock::from_time_t((time_t)until);
        info.failedAttempts = fails;

        // abgelaufene Einträge überspringen
        if (info.blacklistUntil > now)
        {
            LOGIN_MAP[ip] = info;
        }
    }
}

void saveBlacklist()
{
    std::lock_guard<std::mutex> lock(blacklistMutex);

    fs::path file = getBlacklistFile();
    std::ofstream out(file, std::ios::trunc);
    if (!out)
        return;

    auto now = std::chrono::system_clock::now();

    for (const auto &pair : LOGIN_MAP)
    {
        const std::string &ip = pair.first;
        const LoginInfo &info = pair.second;

        if (info.blacklistUntil > now)
        {
            time_t time = std::chrono::system_clock::to_time_t(info.blacklistUntil);
            out << ip << " " << info.failedAttempts << " " << (long long)time << "\n";
        }
    }
}

// Read a line from socket
string readLine(int sock)
{
    string line;
    char c;
    ssize_t n;
    while ((n = recv(sock, &c, 1, 0)) > 0)
    {
        if (c == '\n')
            break;
        if (c != '\r')
            line += c;
    }
    return line;
}

// Send a line to socket
void sendLine(int sock, const string &line)
{
    string msg = line + "\n";
    send(sock, msg.c_str(), msg.length(), 0);
}

// Validate username (max 8 chars, alphanumeric)
bool isValidUsername(const string &username)
{
    if (username.empty() || username.length() > 8)
        return false;
    return regex_match(username, regex("^[a-z0-9]+$"));
}

// Get user inbox path
fs::path getUserInbox(const string &spool, const string &username)
{
    return fs::path(spool) / username;
}

// Get all message files for a user
vector<fs::path> getMessageFiles(const fs::path &inbox)
{
    vector<fs::path> files;
    error_code ec;

    if (!fs::exists(inbox, ec) || !fs::is_directory(inbox, ec))
    {
        return files;
    }

    for (const auto &entry : fs::directory_iterator(inbox, ec))
    {
        if (entry.is_regular_file(ec))
        {
            files.push_back(entry.path());
        }
    }

    sort(files.begin(), files.end());
    return files;
}

// Handle SEND command
void handleSend(int sock, const string &spool, const Session &session)
{
    string receiver = readLine(sock);
    string subject = readLine(sock);

    if (!isValidUsername(receiver))
    {
        sendLine(sock, "ERR");
        return;
    }

    if (subject.length() > 80)
    {
        sendLine(sock, "ERR");
        return;
    }

    // Read message body until "."
    string message;
    string line;
    while (true)
    {
        line = readLine(sock);
        if (line == ".")
            break;
        message += line + "\n";
    }
    {
        // Lockguard damit threadsicher
        std::lock_guard<std::mutex> lock(spoolMutex);

        // Create receiver's inbox
        fs::path inbox = getUserInbox(spool, receiver);
        if (!checkDir(inbox))
        {
            sendLine(sock, "ERR");
            return;
        }

        // Create unique filename (timestamp-based)
        auto now = chrono::system_clock::now();
        auto timestamp = chrono::duration_cast<chrono::milliseconds>(now.time_since_epoch()).count();
        fs::path msgFile = inbox / (to_string(timestamp) + ".txt");

        // Write message to file
        ofstream out(msgFile);
        if (!out)
        {
            sendLine(sock, "ERR");
            return;
        }

        out << "Sender: " << session.username << "\n";
        out << "Receiver: " << receiver << "\n";
        out << "Subject: " << subject << "\n";
        out << "Message:\n"
            << message;
        out.close();
    }
    sendLine(sock, "OK");
}

// Handle LIST command
void handleList(int sock, const string &spool, const Session &session)
{
    string username = session.username;

    vector<fs::path> files;

    {
        // Lockguard damit threadsicher
        std::lock_guard<std::mutex> lock(spoolMutex);

        fs::path inbox = getUserInbox(spool, username);
        files = getMessageFiles(inbox);
    }

    sendLine(sock, to_string(files.size()));

    for (const auto &file : files)
    {
        ifstream in(file);
        if (!in)
            continue;

        string line;
        string subject;

        // Read until we find the subject line
        while (getline(in, line))
        {
            if (line.find("Subject: ") == 0)
            {
                subject = line.substr(9);
                break;
            }
        }

        sendLine(sock, subject.empty() ? "(no subject)" : subject);
    }
}

// Handle READ command
void handleRead(int sock, const string &spool, const Session &session)
{
    string username = session.username;
    string msgNumStr = readLine(sock);

    int msgNum;
    try
    {
        msgNum = stoi(msgNumStr);
    }
    catch (...)
    {
        sendLine(sock, "ERR");
        return;
    }

    vector<fs::path> files;
    {
        // Lockguard damit threadsicher
        std::lock_guard<std::mutex> lock(spoolMutex);

        fs::path inbox = getUserInbox(spool, username);
        files = getMessageFiles(inbox);
    }
    if (msgNum < 1 || msgNum > (int)files.size())
    {
        sendLine(sock, "ERR");
        return;
    }

    ifstream in(files[msgNum - 1]);
    if (!in)
    {
        sendLine(sock, "ERR");
        return;
    }

    sendLine(sock, "OK");

    string line;
    while (getline(in, line))
    {
        sendLine(sock, line);
    }
    sendLine(sock, ".");
}

// Handle DEL command
void handleDelete(int sock, const string &spool, const Session &session)
{
    string username = session.username;
    string msgNumStr = readLine(sock);

    int msgNum;
    try
    {
        msgNum = stoi(msgNumStr);
    }
    catch (...)
    {
        sendLine(sock, "ERR");
        return;
    }
    bool ok = false;

    {
        // Lockguard damit threadsicher
        std::lock_guard<std::mutex> lock(spoolMutex);

        fs::path inbox = getUserInbox(spool, username);
        vector<fs::path> files = getMessageFiles(inbox);

        if (msgNum >= 1 && msgNum <= (int)files.size())
        {
            error_code ec;
            if (fs::remove(files[msgNum - 1], ec))
            {
                ok = true;
            }
        }
    }

    if (ok)
    {
        sendLine(sock, "OK");
    }
    else
    {
        sendLine(sock, "ERR");
    }
}

bool ldapAuthenticate(const std::string &username, const std::string &password)
{

    if (password.empty())
        return false;

    LDAP *ldap = nullptr;
    int rc;

    // Verbindung aufbauen
    rc = ldap_initialize(&ldap, "ldap://ldap.technikum-wien.at:389");
    if (rc != LDAP_SUCCESS || !ldap)
    {
        cerr << "LDAP: initialize failed: " << ldap_err2string(rc) << endl;
        return false;
    }

    int version = LDAP_VERSION3;
    ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &version);

    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    ldap_set_option(ldap, LDAP_OPT_NETWORK_TIMEOUT, &tv);

    std::string userDN = "uid=" + username + ",ou=people,dc=technikum-wien,dc=at";

    // Bind
    struct berval cred;
    cred.bv_val = const_cast<char *>(password.c_str());
    cred.bv_len = password.size();

    rc = ldap_sasl_bind_s(
        ldap,
        userDN.c_str(),
        LDAP_SASL_SIMPLE,
        &cred,
        nullptr,
        nullptr,
        nullptr);

    if (rc != LDAP_SUCCESS)
    {
        std::cerr << "LDAP: bind failed for " << userDN
                  << ": " << ldap_err2string(rc) << std::endl;
    }

    ldap_unbind_ext_s(ldap, nullptr, nullptr);

    return rc == LDAP_SUCCESS;
}

static void handleLogin(int sock, Session &session, const std::string &clientIP)
{
    auto now = std::chrono::system_clock::now();
    // checken ob IP in blacklist ist
    {
        std::lock_guard<std::mutex> lock(blacklistMutex);
        auto it = LOGIN_MAP.find(clientIP);
        if (it != LOGIN_MAP.end() && it->second.blacklistUntil > now)
        {
            // IP ist aktuell gesperrt
            sendLine(sock, "ERR");
            return;
        }
    }

    if (session.authenticated)
    {
        sendLine(sock, "OK");
        return;
    }

    string username = readLine(sock);
    string password = readLine(sock);
    cerr << "[SERVER] LOGIN username='" << username << "'" << endl;

    if (!isValidUsername(username))
    {
        cerr << "[SERVER] INVALID username format" << endl;
        sendLine(sock, "ERR");
        return;
    }

    bool success = ldapAuthenticate(username, password);
    cerr << "[SERVER] ldapAuthenticate returned " << (success ? "true" : "false") << endl;

    if (success)
    {
        session.authenticated = true;
        session.username = username;

        {
            std::lock_guard<std::mutex> lock(blacklistMutex);
            auto it = LOGIN_MAP.find(clientIP);
            if (it != LOGIN_MAP.end())
            {
                it->second.failedAttempts = 0;
                it->second.blacklistUntil = std::chrono::system_clock::time_point{};
            }
        }
        saveBlacklist();
        sendLine(sock, "OK");
    }
    else
    {
        {
            std::lock_guard<std::mutex> lock(blacklistMutex);
            LoginInfo &info = LOGIN_MAP[clientIP];
            // Fehlversuche erhöhen
            info.failedAttempts++;

            if (info.failedAttempts >= 3)
            {
                // IP für 1 min sperren
                info.blacklistUntil = now + std::chrono::minutes(1);
            }
            saveBlacklist();
        }
        sendLine(sock, "ERR");
    }
}

static void handleClient(int c, string spool, std::string clientIP)
{
    Session session; // Session pro Client
    try
    {
        while (true)
        {
            string command = readLine(c);

            if (command.empty())
                break;

            transform(command.begin(), command.end(), command.begin(), ::toupper);

            if (command == "LOGIN")
            {
                handleLogin(c, session, clientIP);
            }
            else if (command == "SEND")
            {
                if (!session.authenticated)
                {
                    sendLine(c, "ERR");
                    continue;
                }
                handleSend(c, spool, session);
            }
            else if (command == "LIST")
            {
                if (!session.authenticated)
                {
                    sendLine(c, "ERR");
                    continue;
                }
                handleList(c, spool, session);
            }
            else if (command == "READ")
            {
                if (!session.authenticated)
                {
                    sendLine(c, "ERR");
                    continue;
                }
                handleRead(c, spool, session);
            }
            else if (command == "DEL")
            {
                if (!session.authenticated)
                {
                    sendLine(c, "ERR");
                    continue;
                }
                handleDelete(c, spool, session);
            }
            else if (command == "QUIT")
            {
                break;
            }
            else
            {
                sendLine(c, "ERR");
            }
        }
    }
    catch (...)
    {
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
    SPOOL_DIR = spool;
    loadBlackList();

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

        thread{handleClient, c, spool, std::string(clientIP)}.detach();
    }

    cout << "\nShutting down server..." << endl;
    shutdown(s, SHUT_RDWR);
    close(s);
    return 0;
}