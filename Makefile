CC = gcc
# Define CFLAGS for libnl-3.0 and libnl-genl-3.0 using pkg-config
CFLAGS_NL = $(shell pkg-config --cflags libnl-3.0 libnl-genl-3.0)
# Define LDLIBS for libnl-3.0 and libnl-genl-3.0 using pkg-config
LDLIBS_NL = $(shell pkg-config --libs libnl-3.0 libnl-genl-3.0)

# Add other CFLAGS like -Wall, -Werror, -O2 if desired
# For this example, we'll keep it simple.
CFLAGS += -Wall $(CFLAGS_NL)
LDLIBS += $(LDLIBS_NL)

TARGET = wifi_scan
SRC = wifi_scan.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDLIBS)

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
