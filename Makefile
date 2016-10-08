BIN = arp_populator
CFLAGS = -g -O2 -Wall -std=gnu99
LDLIBS = -lrt

all: $(BIN)

.PHONY: clean
clean:
	$(RM) $(BIN)
