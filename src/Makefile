include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/package.mk

CC = mips-openwrt-linux-gcc
CFLAGS = -Wall -g -O2
INC_DIR= $(STAGING_DIR)/usr/include -I$(BUILD_DIR)/libpcap-1.5.3/ipkg-install/usr/include
LINK_DIR= $(STAGING_DIR)/usr/lib -L$(BUILD_DIR)/libpcap-1.5.3/ipkg-install/usr/lib
LIBS= $(BUILD_DIR)/libpcap-1.5.3/ipkg-install/usr/lib/libpcap.a

OBJ  = evasi0n.o md5.o myconf.o dyload.o mylock.o strnormalize.o
.PHONY: all

all: evasi0n

evasi0n: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LIBS) -I$(INC_DIR) -L$(LINK_DIR)

evasi0n.o : evasi0n.c
	$(CC) $(CFLAGS) -c $< -I$(INC_DIR)

md5.o        : md5.c md5.h
	$(CC) $(CFLAGS) -c $< -I$(INC_DIR)

strnormalize.o: strnormalize.c strnormalize.h
	$(CC) $(CFLAGS) -c $< -I$(INC_DIR)

myconf.o : myconf.c
	$(CC) $(CFLAGS) -c $< -I$(INC_DIR)

dyload.o : dyload.c
	$(CC) $(CFLAGS) -c $< -I$(INC_DIR)

mylock.o : mylock.c
	$(CC) $(CFLAGS) -c $< -I$(INC_DIR)
        
clean :
	rm -v $(OBJ) evasi0n
