#include <iostream>
using std::string;

int main(int argc, char* argv[]){
    if(argc != 3){
        std::cerr << "Please enter like: " << argv[0] << " <port> <mail-spool-directory>";
        return 1;
    }
    int port = std::atoi(argv[1]);
    if(port <= 1024 || port > 65535){
        std::cerr << "Invalid port, choose between 1025 - 65535";
        return 1;
    }
}