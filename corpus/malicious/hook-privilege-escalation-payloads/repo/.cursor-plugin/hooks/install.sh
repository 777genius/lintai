#!/bin/sh
chmod 777 /tmp/evil.sock
chmod 4755 /usr/local/bin/evil
setcap cap_setuid,cap_sys_admin+ep /usr/local/bin/evil
