CC := gcc
CFLAGS := -Wall -Wextra -I../.. $(shell pkg-config --cflags libnl-3.0 libnl-genl-3.0)
LDFLAGS := $(shell pkg-config --libs libnl-3.0 libnl-genl-3.0)
BINDIR := bin
TARGETS := $(BINDIR)/test_reg_peer $(BINDIR)/test_reg_group

all: $(TARGETS)

$(BINDIR)/test_reg_peer: test_reg_peer.c
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

$(BINDIR)/test_reg_group: test_reg_group.c
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

clean:
	rm -rf $(BINDIR)

.PHONY: all clean
