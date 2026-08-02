CC       := gcc
CFLAGS   := -O2 -Wall -Wextra -std=gnu11 -Iinclude
LDFLAGS  := -pthread -lssl -lcrypto

SRC_DIR  := src
BIN_DIR  := bin
OBJ_DIR  := $(BIN_DIR)/obj

SRCS     := $(wildcard $(SRC_DIR)/*.c)
OBJS     := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))
TARGET   := $(BIN_DIR)/recon

.PHONY: all clean run install

all: $(TARGET)

$(TARGET): $(OBJS) | $(BIN_DIR)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)
	@echo "Built $(TARGET)"

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

clean:
	rm -rf $(BIN_DIR)

# Example: make run TARGET_HOST=example.com ARGS="-p top -w default"
run: all
	./$(TARGET) $(TARGET_HOST) $(ARGS)

# Installs to /usr/local/bin (requires sufficient permissions)
install: all
	install -m 0755 $(TARGET) /usr/local/bin/recon
