#!/bin/sh

mkdir -p ~/.config/systemd/user
cp cifsd.service ~/.config/systemd/user
systemctl --user daemon-reload
