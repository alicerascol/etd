# Evil Twin Detector (ETD) 

_Written by: Mike Cromwell_

The Evil Twin Detector monitors for devices that are trying to spoof your existing 
wireless access points, if any are found a notification is sent by email and/or syslog over UDP.

## Requirements

## Software

- Linux (could potentially run on other posix systems)
- Python 2.7
- systemd
- pip

## Wireless Adapter

Wireless Adapter that supports monitoring, I have been using the Alfa AWUS051NH and have managed
to get this working on both 2.4 & 5Ghz bands. I would imagine any of the usual wireless adapters that
get mentioned for hacking on Kali would work fine.

## Install

```commandline
git clone https://github.com/stavinski/etd.git && cd etd
```

ETD can run in 2 modes standalone or as a systemd daemon service.

### Standalone

```commandline
sudo python etd.py
```

_Note that the script must be ran as root._

### Service

```commandline
sudo ./setup.sh install
```

The existing etd.yaml config file will be copied into _/etc/etd_ so any changes made for the service should be made here and the service restarted

## Configuration

ETD uses a yaml config file, when you clone the repo it has a baseline version called _etd.py_, 
these will need to be tailored to your environment.

### Global

- **include_5ghz:** (_bool_) 
- **wlan_iface:** (_string_) defaults to 'wlan0' but you will want this to be the iface associated with your wireless adapter
- **mon_iface:** (_string_) defaults to 'mon0' this is the name that the created monitor iface will use change only if it conflicts
- **5ghz_channels:** (_list_) this can be changed for your region

### Logging

- **level:** (_string_) defaults to 'WARN', but can be changed to standard logging levels
- **name:*** (_string_) defaults to 'Evil Twin Detector'

### SMTP

- **enabled:** (_bool_) defaults to No
- **server:** (_string_) defaults to 'localhost'
- **port:** (_int_) defaults to 25
- **user:** (_string_) defaults to EMPTY
- **password:** (_string_) defaults to EMPTY
- **from**: (_string_) defaults to 'etd@localhost'
- **to**: (_string_) defaults to 'root@localhost'
- **subject**: (_string_) defaults to 'ETD DETECTION'

### Syslog

- **enabled:** (_bool_) defaults to No
- **server:** (_string_) defaults to 'localhost'
- **port:** (_int_) defaults to 514

### Ignores

Contains a list of MAC addresses for wireless access points that you expect to be using an SSID you are pattern matching against
so that you don't get false positives.

## Patterns

Contains a list of strings that should be pattern matched against the SSID being broadcast so that you can filter which devices
are actively trying to spoof known wireless access points.
