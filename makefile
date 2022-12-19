# Ubuntu 18.04 (on Windows hyper-v server)에서 g++8 버전 컴파일 테스트가 되었음
all:
	g++ mini_shell.cpp -o mini_shell -std=c++17 -lstdc++fs -O3
clean:
	rm mini_shell