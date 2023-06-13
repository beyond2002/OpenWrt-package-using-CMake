#!/bin/sh

/bin/echo "=============================="
/bin/echo "Timestamp: $(date)"
/bin/echo "Checking license ..."

if ! /usr/bin/licensecheck; then
    /bin/echo " failed!!!"
    reboot
fi

/bin/echo "success!"
/bin/echo "=============================="
