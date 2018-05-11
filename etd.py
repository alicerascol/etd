#!/usr/bin/env python
# coding=utf-8

import os
import sys
import time
import threading
import random
import binascii
import fnmatch
import subprocess
import yaml

from scapy.all import *
from argparse import ArgumentParser

# consts
CH_SLEEP_INT = 0.5

# globals
verbose = False
detections = {}
config = {}


class Detection:

    def __init__(self, **kwargs):
        self.bssid = kwargs.get("bssid")
        self.essid = kwargs.get("essid")
        self.enc = kwargs.get("enc")
        self.rssi = kwargs.get("rssi")
        self.channel = kwargs.get("channel")

    def encs_str(self):
        return "|".join(self.enc)

    def __str__(self):
        return "{0:5}\t{1:20}\t{2:20}\t{3:5}\t{4:4}".format(self.channel, self.bssid, self.essid, self.rssi, self.encs_str())

    def __repr__(self):
        return "channel: {}, bssid: {}, essid: {}, rssi: {}, enc: {}".format(self.channel, self.bssid, self.essid, self.rssi, self.encs_str())


# ran in separate thread periodically changing device channel
def channel_hopper():

    iface = config["mon_iface"]
    use_5ghz = config["include_5ghz"]
    channels = list(range(1, 14))

    # if we need to add the 5ghz channels in
    if use_5ghz:
        additional = config["5ghz_channels"]
        channels.extend(map(int, additional))

    while True:
        try:
            channel = random.choice(channels)
            subprocess.call("iw dev %s set channel %d" % (iface, channel), shell=True, stderr=subprocess.PIPE)
            time.sleep(CH_SLEEP_INT)
        except subprocess.CalledProcessError as e:
            print "[!] exit code: %d" % e.returncode
            break


def parse_config(conf_file):
    global config

    with open(conf_file, "r") as ymlfile:
        cfg = yaml.load(ymlfile)
        glo = cfg["global"]

        config = {
            "iface": glo["wlan_iface"],
            "mon_iface": glo["mon_iface"],
            "include_5ghz": glo["include_5ghz"],
            "5ghz_channels": glo["5ghz_channels"],
            "use_smtp": glo["use_smtp"],
            "detections_log": glo["detections_log"],
            "ignores": cfg["ignores"],
            "patterns": cfg["patterns"]
        }

    #print config["ignores"]
    #print config["patterns"]


def set_monitoring_mode():
    wlan_iface = config["iface"]
    mon_iface = config["mon_iface"]

    print "[*] setting device into monitor mode"

    if verbose:
        print "[!] bringing %s device down" % wlan_iface

    os.system("ifconfig %s down" % wlan_iface)
    os.system("iw dev %s interface add %s type monitor" % (wlan_iface, mon_iface))

    if verbose:
        print "[!] monitor device %s created" % mon_iface

    time.sleep(5)

    if verbose:
        print "[!] bringing %s monitor down" % mon_iface

    os.system("ifconfig %s down" % mon_iface)

    os.system("iw dev %s set type monitor" % mon_iface)
    if verbose:
        print "[!] bringing %s monitor up" % mon_iface

    os.system("ifconfig %s up" % mon_iface)


def remove_monitoring_device():
    iface = config["mon_iface"]
    print "[*] removing monitoring interface"
    os.system("iw %s del" % iface)


def ssid_matches_patterns(ssid):
    patterns = config["patterns"]
    return any((fnmatch.fnmatch(ssid, pattern) for pattern in patterns))


def packet_handler(pkt):
    if not pkt.haslayer(Dot11Elt):
        return

    essid = pkt[Dot11Elt].info if '\x00' not in pkt[Dot11Elt].info and pkt[Dot11Elt].info != '' else '<hidden>'
    bssid = pkt[Dot11].addr3

    try:
        channel = int(ord(pkt[Dot11Elt:3].info))
    except:
        channel = 0

    try:
        extra = pkt.notdecoded
        rssi = -(256 - ord(extra[-4:-3]))
    except:
        rssi = -100

    p = pkt[Dot11Elt]

    capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").split('+')

    crypto = set()
    while isinstance(p, Dot11Elt):
        if p.ID == 48:
            crypto.add("WPA2")
        elif p.ID == 221 and p.info.startswith('\x00P\xf2\x01\x01\x00'):
            crypto.add("WPA")
        p = p.payload

    if not crypto:
        if 'privacy' in capability:
            crypto.add("WEP")
        else:
            crypto.add("OPN")

    # already been detected
    if bssid in detections:
        return

    if ssid_matches_patterns(essid) and bssid not in config["ignores"]:
        detection = Detection(essid=essid, bssid=bssid, enc=crypto, rssi=rssi, channel=channel)
        detections[bssid] = detection
        print "[+] %s" % detection


def start_sniffing():
    iface = config["mon_iface"]
    sniff(iface=iface, filter="type mgt and subtype beacon", store=False, prn=packet_handler)


def main(args):

    parse_config(args.config)
    hopper_thread = threading.Thread(target=channel_hopper)
    hopper_thread.setDaemon(True)

    try:
        set_monitoring_mode()
        hopper_thread.start()
        start_sniffing()
    finally:
        remove_monitoring_device()


if __name__ == "__main__":

    if os.name == "nt":
        sys.exit("[!] windows not supported")

    if os.getuid() != 0:
        sys.exit("[!] must be ran with root privileges")

    parser = ArgumentParser(description="Evil Twin Detector tool - Mike Cromwell 2018")

    parser.add_argument("-v", "--verbose", help="add extra logging", default=False, action="store_true")
    parser.add_argument("-c", "--config", help="use different config file", type=str, default="etd.yaml")

    args = parser.parse_args()
    verbose = args.verbose
    main(args)
