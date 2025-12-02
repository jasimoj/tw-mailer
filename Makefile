CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2

all: twmailer-server twmailer-client
twmailer-server: twmailer-server.cpp
	$(CXX) $(CXXFLAGS) -o twmailer-server twmailer-server.cpp -lldap -llber

twmailer-client: twmailer-client.cpp
	$(CXX) $(CXXFLAGS) -o twmailer-client twmailer-client.cpp

clean:
	rm -f twmailer-server twmailer-client
