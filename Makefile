#
# Copyright (C) 2014-2015 KyleRicardo
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=evasi0n
PKG_VERSION:=1.0
PKG_RELEASE:=1


PKG_FIXUP:=autoreconf

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/evasi0n
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+libpcap +libstdcpp
  TITLE:=A Digital China Client Daemon
  URL:=http://code.google.com/p/evasi0n/
  SUBMENU:=DigitalChina
endef

define Package/evasi0n/description
A Digital China Client Daemon,
Most usually used in China collages.
endef

CONFIGURE_ARGS += \
	--disable-notify


define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/evasi0n/conffiles
/jffs/etc/evasi0n.conf
endef

define Build/Compile
	#$(Build/Compile/$(PKG_NAME))
	$(MAKE) -C $(PKG_BUILD_DIR)/ \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="$(TARGET_CPPFLAGS)"  \
		LDFLAGS="$(TARGET_LDFLAGS) -ldl"
endef

define Package/evasi0n/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/evasi0n $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/jffs/etc
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/evasi0n.conf $(1)/jffs/etc/evasi0n.conf

endef

$(eval $(call BuildPackage,$(PKG_NAME)))
