#include <iostream>
using std::string;

int main(int argc, char* argv[]){
    if(argc != 3){
        std::cerr << "Please enter like: " << argv[0] << " <ip> <port>";
        return 1;
    }
}