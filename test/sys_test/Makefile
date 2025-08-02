CC := gcc
CFLAGS := -Wall -Wextra -I../../include -I../../ $(shell pkg-config --cflags libnl-3.0 libnl-genl-3.0)
LDFLAGS := $(shell pkg-config --libs libnl-3.0 libnl-genl-3.0)
BINDIR := bin
TARGETS := $(BINDIR)/test_reg_peer $(BINDIR)/test_reg_group $(BINDIR)/test_grp_resolve

all: $(TARGETS)

$(BINDIR)/test_reg_peer: test_reg_peer.c
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

$(BINDIR)/test_reg_group: test_reg_group.c
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

$(BINDIR)/test_grp_resolve: test_grp_resolve.c
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

clean:
	rm -rf $(BINDIR)

.PHONY: all clean
