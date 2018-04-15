#!/usr/bin/env python
# coding=utf-8

import os
import sys
import time
import threading
import random
import binascii
import fnmatch

from ConfigParser import ConfigParser
from binascii import hexlify
from scapy.all import *
from argparse import ArgumentParser

# globals
verbose = False
aps = []

# consts
SECTIONS_GLOBAL = "global"
SECTIONS_SMTP = "smtp"
SECTIONS_IGNORE = "ignore"
SECTIONS_PATTERNS = "patterns"

# ran in separate thread peridocally changing device channel
def channel_hopper(conf):
  mon_device = conf.get(SECTIONS_GLOBAL, "mon_device", "mon0")
  use_5ghz = conf.getboolean(SECTIONS_GLOBAL, "include_5ghz")
  channels = list(range(1, 14))

  # if we need to add the 5ghz channels in
  if use_5ghz:
    additional = conf.get(SECTIONS_GLOBAL, "5ghz_channels")
    channels.extend([int(x) for x in additional.split(",")])

  while True:
    try:
      channel = random.choice(channels)
      os.system("iw dev %s set channel %d" % (mon_device, channel))
      time.sleep(1)
    except KeyboardInterrupt:
      break


def get_mac_str(arr):
  s = hexlify(arr)
  t = iter(s)
  st = ':'.join(a+b for a,b in zip(t,t))
  return st


def parse_config(conf_file):
  config = ConfigParser()
  config.read(conf_file)
  return config


def set_monitoring_mode(conf):
  wlan_device = conf.get(SECTIONS_GLOBAL, "wlan_device", "wlan0")
  mon_device = conf.get(SECTIONS_GLOBAL, "mon_device", "mon0")

  print "[*] setting device into monitor mode"

  if verbose:
    print "[!] bring %s device down" % wlan_device

  os.system("ifconfig %s down" % wlan_device)
  os.system("iw dev %s interface add %s type monitor" % (wlan_device, mon_device))

  if verbose:
    print "[!] monitor device %s created" % mon_device

  time.sleep(5)

  if verbose:
    print "[!] bringing %s monitor down" % mon_device

  os.system("ifconfig %s down" % mon_device)

  os.system("iw dev %s set type monitor" % mon_device)
  if verbose:
    print "[!] bringing %s monitor up" % mon_device

  os.system("ifconfig %s up" % mon_device)


def remove_monitoring_device(conf):
  mon_device = conf.get(SECTIONS_GLOBAL, "mon_device", "mon0")
  print "[*] removing monitoring device"
  os.system("iw %s del" % mon_device)


def ssid_matches_patterns(conf, ssid):
  patterns = conf.options("patterns")
  return any((fnmatch.fnmatch(ssid, pattern) for pattern in patterns))


def packet_handler(pkt):
  ssid = pkt[Dot11Elt].info
  bssid = pkt[Dot11].addr3
  channel = int( ord(pkt[Dot11Elt:3].info))

  if not bssid in aps:
    aps.append(bssid)
    print "CH: %i BSSID: %s - SSID: %s" % (channel, bssid, ssid)


def start_sniffing(conf):
  mon_device = conf.get(SECTIONS_GLOBAL, "mon_device", "mon0")
  sniff(iface=mon_device, filter="type mgt and subtype beacon", store=0, prn=packet_handler)


def main(args):
  conf = parse_config(args.config)
  t_chopper = threading.Thread(target=channel_hopper, args=(conf,))

  try:
    set_monitoring_mode(conf)
    t_chopper.daemon = True
    t_chopper.start()
    start_sniffing(conf)
  except KeyboardInterrupt:
    sys.exit("[!] exiting")
  finally:
    remove_monitoring_device(conf)


if __name__ == "__main__":

  if os.name == "nt":
    sys.exit("[!] windows not suppored")

  if os.getuid() != 0:
    sys.exit("[!] must be ran with root priveleges")

  parser = ArgumentParser(description="EvilTwin Detector tool - Mike Cromwell 2018")

  parser.add_argument("-v", "--verbose", help="add extra logging", default=False, action="store_true")
  parser.add_argument("-c", "--config", help="use different config file", type=str, default="etd.conf")

  args = parser.parse_args()
  verbose = args.verbose
  main(args)
