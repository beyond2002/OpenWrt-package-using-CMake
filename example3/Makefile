include $(TOPDIR)/rules.mk

PKG_NAME:=example3
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/open-license-manager/examples.git
PKG_SOURCE_VERSION:=develop

PKG_MAINTAINER:=Gabriele Contini <youremail@example.com>
PKG_LICENSE:=GPL-2.0-or-later
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/example3
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=submodule of license manager
	URL:=https://github.com/open-license-manager/examples.git
endef

define Package/example3/description
	Examples of open-license-manager
endef

define Build/Configure
	(cd $(PKG_BUILD_DIR)/submodule/build; \
	cmake -DLCC_PROJECT_NAME=submodule -DCMAKE_PREFIX_PATH=$(STAGING_DIR)/usr \
	.. \
	)
endef

define Build/Compile
	(cd $(PKG_BUILD_DIR)/submodule/build; \
	cmake --build . \
	)
endef

define Package/example3/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/submodule/build/example $(1)/usr/bin/
endef

$(eval $(call BuildPackage,example3))
