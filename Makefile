BIN = arp_populator
CFLAGS = -g -O2 -Wall -std=gnu99

all: $(BIN)

.PHONY: clean
clean:
	$(RM) $(BIN)
