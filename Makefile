UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
SYSROOT ?= $(shell xcodebuild -sdk macosx -version Path 2> /dev/null)
endif

LDFLAGS := -L$(SYSROOT)/usr/lib -lc
CFLAGS := -g -I$(SRC_DIR) -03

ifeq ($(UNAME_S),Darwin)
CFLAGS += -isysroot $(SYSROOT)
else
CFLAGS += -Iapple-include
endif

OUTPUT_DIR = output
BUILD_DIR = build
EXECUTABLE = $(OUTPUT_DIR)/kpf
SRC_DIR = kpf
SOURCES = $(shell find $(SRC_DIR) -type f ! -name "*.h")
OBJS = $(SOURCES:%=$(BUILD_DIR)/%.o)

$(BUILD_DIR)/%.o: %
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(EXECUTABLE): $(OBJS)
	mkdir -p $(dir $@)
	ld $(LDFLAGS) $(OBJS) -o $(EXECUTABLE)

clean:
	rm -rf $(BUILD_DIR) $(OUTPUT_DIR)
