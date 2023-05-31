include $(TOPDIR)/rules.mk

PKG_NAME:=example3
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/beyond2002/examples.git
PKG_SOURCE_VERSION:=develop

PKG_MAINTAINER:=Gabriele Contini <youremail@example.com>
PKG_LICENSE:=GPL-2.0-or-later
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_PARALLEL:=0

CMAKE_OPTIONS=-D LCC_PROJECT_NAME=submodule \
			  -D CMAKE_PREFIX_PATH=$(STAGING_DIR)/usr \
			  -D CMAKE_VERBOSE_MAKEFILE=ON \
			  -D CMAKE_CROSSCOMPILING_EMULATOR=""

CMAKE_BINARY_SUBDIR:=submodule/build
CMAKE_SOURCE_SUBDIR:=submodule

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/example3
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=submodule of license manager
	URL:=https://github.com/open-license-manager/examples.git
	DEPENDS:=+libstdcpp
endef

define Package/example3/description
	Examples of open-license-manager
endef

define Package/example3/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/submodule/build/example $(1)/usr/bin/
	# lccgen will be built only when boost exists
	if [ -e $(PKG_BUILD_DIR)/ipkg-install/usr/bin/lccgen ]; then \
		$(INSTALL_BIN) $(PKG_BUILD_DIR)/ipkg-install/usr/bin/lccgen $(1)/usr/bin/; \
	fi
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ipkg-install/usr/bin/submodule/lccinspector $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/ipkg-install/usr/lib/licensecc/submodule/liblicensecc_static.a $(1)/usr/lib
endef

$(eval $(call BuildPackage,example3))
