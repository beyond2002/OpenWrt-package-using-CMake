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
  DEPENDS:=
endef

define Package/example3/description
  Examples of open-license-manager
endef

define Build/Configure
  $(call Build/Configure/Default)
endef

define Build/Compile
  $(MAKE) -C $(PKG_BUILD_DIR)
endef

define Package/submodule/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/example $(1)/usr/bin/
endef

$(eval $(call BuildPackage,submodule))
