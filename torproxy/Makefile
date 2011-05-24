# 
# Copyright (C) 2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id: Makefile $

include $(TOPDIR)/rules.mk

PKG_NAME:=torproxy
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/torproxy/Default
	SECTION:=net
	CATEGORY:=Network
	URL:=http://crypto.stanford.edu/cs294s/projects/yiannis.html
endef

define Packet/torproxy/Default/description
	A basic proxy/forwarder for Tor.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

define Package/torproxy
  $(call Package/torproxy/Default)
  TITLE:=Tor Proxy Utility
endef

define Packet/torproxy/description
	A basic proxy/forwarder for Tor.
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS) -std=c99" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		LDFLAGS_MODULES="$(TARGET_LDFLAGS)" \
		PRECOMPILED_FILTER=1 \
		STAGING_DIR="$(STAGING_DIR)" \
		DESTDIR="$(PKG_INSTALL_DIR)/usr" \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		PATH="$(TARGET_PATH)" \
		KCC="$(KERNEL_CC)"
endef

define Package/torproxy/install
	$(INSTALL_DIR) $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/fwder $(1)/usr/bin/
endef

$(eval $(call BuildPackage,torproxy))
