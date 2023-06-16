include $(TOPDIR)/rules.mk

PKG_NAME:=licenseclient
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Gabriele Contini <youremail@example.com>
PKG_LICENSE:=GPL-2.0-or-later
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_PARALLEL:=0

CMAKE_OPTIONS=-D LCC_PROJECT_NAME=licenseclient \
			  -D CMAKE_PREFIX_PATH=$(STAGING_DIR)/usr \
			  -D CMAKE_VERBOSE_MAKEFILE=ON \
			  -D CMAKE_CROSSCOMPILING_EMULATOR=""

CMAKE_BINARY_SUBDIR:=build

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/licenseclient
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=client of license manager
	URL:=https://github.com/beyond2002/licenseclient.git
	DEPENDS:=+libstdcpp
endef

define Package/licenseclient/description
	client of license manager system
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./files/* $(PKG_BUILD_DIR)/
endef

define Package/licenseclient/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/build/licensecheck $(1)/usr/bin/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/src/licensecheck.lic $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/licenseguard.sh $(1)/usr/bin/
	# lccgen will be built only when boost exists
	if [ -e $(PKG_BUILD_DIR)/ipkg-install/usr/bin/lccgen ]; then \
		$(INSTALL_BIN) $(PKG_BUILD_DIR)/ipkg-install/usr/bin/lccgen $(1)/usr/bin/; \
	fi
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ipkg-install/usr/bin/licenseclient/lccinspector $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/ipkg-install/usr/lib/licensecc/licenseclient/liblicensecc_static.a $(1)/usr/lib
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/licenseclient.default $(1)/etc/uci-defaults/licenseclient
endef

$(eval $(call BuildPackage,licenseclient))
