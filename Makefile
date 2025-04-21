CC = gcc
CFLAGS = -Wall -Wextra -g # -g adds debug symbols
LDLIBS = -lssl -lcrypto # Add SSL libraries
BUILD_DIR = build

TARGET_SERVER = $(BUILD_DIR)/server
TARGET_CLIENT = $(BUILD_DIR)/client
SOURCES_SERVER = server.c
SOURCES_CLIENT = client.c

all: $(TARGET_SERVER) $(TARGET_CLIENT)

$(TARGET_SERVER): $(SOURCES_SERVER) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

$(TARGET_CLIENT): $(SOURCES_CLIENT) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

# Create the build directory if it doesn't exist
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR) *.o

.PHONY: all clean
