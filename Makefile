flags=-g3 -Wall -ansi -pedantic -D_GNU_SOURCE -lrt -lcrypto

all: icmptx

icmptx: it.o icmptx.cpp tun_dev.o it_protocol.o it_crypto.o
	g++ $(flags) -o icmptx icmptx.cpp it.o tun_dev.o it_protocol.o it_crypto.o

it_protocol.o: it_protocol.cpp it_protocol.h
	g++ $(flags) -c it_protocol.cpp

it_crypto.o: it_crypto.cpp it_crypto.h
	g++ $(flags) -c it_crypto.cpp

it.o: it.cpp tun_dev.h it_protocol.h
	g++ $(flags) -c it.cpp

tun_dev.o: tun_dev.cpp
	g++ $(flags) -c tun_dev.cpp

clean:
	rm -f it_crypto.o it_protocol.o tun_dev.o it.o icmptx
