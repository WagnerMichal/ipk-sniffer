build:
	gcc -o ipk-sniffer ipk-sniffer.c -lpcap
clean:
	rm ipk-sniffer
