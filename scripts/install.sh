#!/bin/sh

mkdir -p ~/.config/systemd/user
cp cifsd.service ~/.config/systemd/user
systemctl --user daemon-reload

echo "Run 'systemctl --user start cifsd.service' to start the service"
echo "Run 'systemctl --user start cifsd.service' to stop the service"
