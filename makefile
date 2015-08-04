crypto_tool: main.o crypto.o crypto_pem_pubkey.o
	g++ -g3 -o crypto_tool main.o crypto.o crypto_pem_pubkey.o -lssl -Wall -fmessage-length=0  -Wreturn-type -MMD -MP -O0

crypto.o: crypto_pem_pubkey.o crypto.cpp crypto.hpp
	g++ -O0 -g3 -Wall -c -MMD -MP crypto.cpp

crypto_pem_pubkey.o: crypto_pem_pubkey.cpp
	g++ -O0 -g3 -Wall -c -MMD -MP crypto_pem_pubkey.cpp

main.o: main.cpp
	g++ -O0 -g3 -Wall -c -MMD -MP main.cpp

clean:
	rm *.o *.d crypto_tool
