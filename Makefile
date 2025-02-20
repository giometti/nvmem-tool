TARGET = nvmem-tool
OBJS = nvmem-tool.o fixed-layout.o

VERSION := $(shell git describe --tags --abbrev=10 \
			--dirty --long --always 2> /dev/null || \
				echo "v0.0.0")
CFLAGS += -O -Wall -Werror -D_GNU_SOURCE -D__VERSION=\"$(VERSION)\"

PREFIX ?= /usr

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LFLAGS)

install: $(TARGET)
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp $< $(DESTDIR)$(PREFIX)/bin/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all install uninstall clean
