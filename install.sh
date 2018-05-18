#!/usr/bin/env bash

# installs ETD as a service for systemd

SVC_NAME="etd.service"

if [[ $EUID -ne 0 ]]; then
    echo "run with root!"
    exit 1
fi

# pip requirements
if [[ ! -x /usr/bin/pip ]]; then
    echo "pip must be installed first!"
    exit 1
fi

echo "installing pip requirements for root user"
sudo -H pip install -r requirements.txt

echo "copying etd.py into /usr/bin"
cp etd.py /usr/bin

if [[ ! -d /etc/etd ]]; then
    echo "/etc/etd not found, creating directory"
    mkdir -p /etc/etd
fi

echo "copying etd.yaml into /etc/etd"
cp etd.yaml /etc/etd

echo "copying $SVC_NAME into /lib/systemd/system"
cp $SVC_NAME /lib/systemd/system

echo "systemd daemon reload"
systemctl daemon-reload

read -p "enable service: (y)" enable

case $enable in
    y|Y)
        systemctl enable $SVC_NAME
        read -p "start service: (y)" start
        case $start in
            y|Y) systemctl start $SVC_NAME;;
        esac
        ;;
esac

echo "installed successfully"
