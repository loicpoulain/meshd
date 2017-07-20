CC := gcc
CPPFLAGS = `pkg-config glib-2.0 --cflags`
CFLAGS := `pkg-config glib-2.0 --cflags` -Wall -g
LDFLAGS = `pkg-config glib-2.0 --libs`
LDFLAGS = -lglib-2.0

CONF_CRYPTO := linux-kernel

# Main Stack
meshd-objs = \
	src/main.o \
	src/network.o \
	src/transport-low.o \
	src/transport-up.o \
	src/access.o \
	src/provision.o \
	src/provision-generic.o \
	src/bearer-adv.o \
	src/workqueue.o \
	src/advertisers/hci-channel.o \
	src/crypto-$(CONF_CRYPTO).o

# Models
meshd-objs += \
	src/models/configuration-server.o \
	src/models/configuration-client.o \
	src/models/health-server.o \
	src/models/health-client.o

bluez-objs = \
	src/external/bluez/io-glib.o \
	src/external/bluez/hci.o \
	src/external/bluez/queue.o \
	src/external/bluez/util.o \
	src/external/bluez/ecc.o

bluez-sharedlib = src/external/bluez-sharedlib.a

test-objs = \
	src/unit/test-crypto.o \
	src/external/bluez/ecc.o \
	src/external/bluez/util.o \
	src/crypto-$(CONF_CRYPTO).o

all: meshd

meshd: $(meshd-objs) $(bluez-sharedlib)
	$(CC) $(meshd-objs) $(bluez-sharedlib) $(LDFLAGS) $(CFLAGS) -o $@

test: $(test-objs)
	$(CC) $(test-objs) $(LDFLAGS) $(CFLAGS) -o $@

%.o : %.c
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ -c $<

$(bluez-sharedlib): $(bluez-objs)
	$(AR) rcs $@ $^

clean:
	rm -R -f src/*~ src/*.o meshd
	rm -R -f src/external/bluez/*~ src/external/bluez/*.o meshd
	rm -R -f src/external/*.a
