OBJECTS  = hw4.o
CFLAGS  += -O2 -Wall -Wextra
LDLIBS  += -lmbedx509 -lmbedcrypto

.PHONY: all clean

all: hw4

hw4: $(OBJECTS)

clean:
	rm -f $(OBJECTS) hw4
