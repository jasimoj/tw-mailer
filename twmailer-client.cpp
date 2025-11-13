#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <string>
#include <sstream>

using namespace std;

// Helper function to read a line from socket
string readLine(int sock) {
    string line;
    char c;
    while (recv(sock, &c, 1, 0) > 0) {
        if (c == '\n') break;
        line += c;
    }
    return line;
}

// Helper function to send a line to socket
bool sendLine(int sock, const string& line) {
    string msg = line + "\n";
    return send(sock, msg.c_str(), msg.length(), 0) > 0;
}

void handleSend(int sock) {
    string sender, receiver, subject, message, line;

    cout << "Sender: ";
    getline(cin, sender);
    if (sender.length() > 8) {
        cerr << "Sender username too long (max 8 chars)" << endl;
        return;
    }

    cout << "Receiver: ";
    getline(cin, receiver);
    if (receiver.length() > 8) {
        cerr << "Receiver username too long (max 8 chars)" << endl;
        return;
    }

    cout << "Subject: ";
    getline(cin, subject);
    if (subject.length() > 80) {
        cerr << "Subject too long (max 80 chars)" << endl;
        return;
    }

    cout << "Message (end with a line containing only '.'):" << endl;
    message = "";
    while (true) {
        getline(cin, line);
        if (line == ".") break;
        message += line + "\n";
    }

    // Send SEND command
    sendLine(sock, "SEND");
    sendLine(sock, sender);
    sendLine(sock, receiver);
    sendLine(sock, subject);
    send(sock, message.c_str(), message.length(), 0);
    sendLine(sock, ".");

    // Read response
    string response = readLine(sock);
    if (response == "OK") {
        cout << "Message sent successfully" << endl;
    } else {
        cout << "Error sending message" << endl;
    }
}

void handleList(int sock) {
    string username;

    cout << "Username: ";
    getline(cin, username);
    if (username.length() > 8) {
        cerr << "Username too long (max 8 chars)" << endl;
        return;
    }

    // Send LIST command
    sendLine(sock, "LIST");
    sendLine(sock, username);

    // Read response
    string countStr = readLine(sock);
    int count = stoi(countStr);

    if (count == 0) {
        cout << "No messages" << endl;
    } else {
        cout << "Messages (" << count << "):" << endl;
        for (int i = 0; i < count; i++) {
            string subject = readLine(sock);
            cout << (i + 1) << ": " << subject << endl;
        }
    }
}

void handleRead(int sock) {
    string username, messageNum;

    cout << "Username: ";
    getline(cin, username);
    if (username.length() > 8) {
        cerr << "Username too long (max 8 chars)" << endl;
        return;
    }

    cout << "Message number: ";
    getline(cin, messageNum);

    // Send READ command
    sendLine(sock, "READ");
    sendLine(sock, username);
    sendLine(sock, messageNum);

    // Read response
    string response = readLine(sock);
    if (response == "OK") {
        cout << "\n=== Message ===" << endl;
        string line;
        while (true) {
            line = readLine(sock);
            if (line.empty() && recv(sock, nullptr, 0, MSG_PEEK) <= 0) break;
            cout << line << endl;
        }
    } else {
        cout << "Error reading message" << endl;
    }
}

void handleDelete(int sock) {
    string username, messageNum;

    cout << "Username: ";
    getline(cin, username);
    if (username.length() > 8) {
        cerr << "Username too long (max 8 chars)" << endl;
        return;
    }

    cout << "Message number: ";
    getline(cin, messageNum);

    // Send DEL command
    sendLine(sock, "DEL");
    sendLine(sock, username);
    sendLine(sock, messageNum);

    // Read response
    string response = readLine(sock);
    if (response == "OK") {
        cout << "Message deleted successfully" << endl;
    } else {
        cout << "Error deleting message" << endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        cerr << "Usage: " << argv[0] << " <ip> <port>" << endl;
        return 1;
    }

    string ip = argv[1];
    int port = atoi(argv[2]);

    if (port <= 1024 || port > 65535) {
        cerr << "Invalid port, choose between 1025 - 65535" << endl;
        return 1;
    }

    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        cerr << "Error creating socket" << endl;
        return 1;
    }

    // Setup server address
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr) <= 0) {
        cerr << "Invalid IP address" << endl;
        close(sock);
        return 1;
    }

    // Connect to server
    if (connect(sock, (sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        cerr << "Error connecting to server" << endl;
        close(sock);
        return 1;
    }

    cout << "Connected to server " << ip << ":" << port << endl;
    cout << "Available commands: SEND, LIST, READ, DEL, QUIT" << endl;

    // Main loop
    string command;
    while (true) {
        cout << "\nCommand: ";
        getline(cin, command);

        // Convert to uppercase
        transform(command.begin(), command.end(), command.begin(), ::toupper);

        if (command == "SEND") {
            handleSend(sock);
        } else if (command == "LIST") {
            handleList(sock);
        } else if (command == "READ") {
            handleRead(sock);
        } else if (command == "DEL") {
            handleDelete(sock);
        } else if (command == "QUIT") {
            sendLine(sock, "QUIT");
            cout << "Disconnecting..." << endl;
            break;
        } else {
            cout << "Unknown command. Available: SEND, LIST, READ, DEL, QUIT" << endl;
        }
    }

    shutdown(sock, SHUT_RDWR);
    close(sock);
    return 0;
}