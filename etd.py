#!/usr/bin/env python
# coding=utf-8

import os
import sys
import time
import threading
import signal
import random
import binascii
import fnmatch
import scapy_ex

from ConfigParser import ConfigParser
from binascii import hexlify
from scapy.all import *
from scapy_ex import * # wifi extensions
from argparse import ArgumentParser

# globals
verbose = False
stopper = None
t_chopper = None
aps = []
config = {}

# ran in separate thread peridocally changing device channel
def channel_hopper():
  global stopper

  iface = config["mon_iface"]
  use_5ghz = config["include_5ghz"]
  channels = list(range(1, 14))

  # if we need to add the 5ghz channels in
  if use_5ghz:
    additional = config["5ghz_channels"]
    channels.extend([int(x) for x in additional.split(",")])

  if verbose:
    print "[*] channel hopper started"

  while not stopper.is_set():
    try:
      channel = random.choice(channels)
      os.system("iw dev %s set channel %d" % (iface, channel))
      time.sleep(1)
    except e:
      print "[!] error channel hopping: %s" % e

  if verbose:
    print "[*] channel hopper stopped"


def parse_config(conf_file):
  global config
  
  global_section = "global"
  
  cfg_parser = ConfigParser(allow_no_value=True)
  cfg_parser.read(conf_file)
  
  config = {
    "iface": cfg_parser.get(global_section, "wlan_iface", "wlan0"),
    "mon_iface": cfg_parser.get(global_section, "mon_iface", "mon0"),
    "include_5ghz": cfg_parser.getboolean(global_section, "include_5ghz"),
    "5ghz_channels": cfg_parser.get(global_section, "5ghz_channels"),
    "use_smtp": cfg_parser.getboolean(global_section, "use_smtp"),
    "detections_log": cfg_parser.get(global_section, "detections_log"),
    "ignores": cfg_parser.items("ignores"),
    "patterns": cfg_parser.options("patterns")
  }

def set_monitoring_mode(conf):
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
    print "[!] bringing %s monitor up" % mon_device

  os.system("ifconfig %s up" % mon_iface)


def remove_monitoring_device():
  iface = config["mon_iface"]
  print "[*] removing monitoring interface"
  os.system("iw %s del" % iface )


def ssid_matches_patterns(ssid):
  patterns = config["patterns"]
  return any((fnmatch.fnmatch(ssid, pattern) for pattern in patterns))


def packet_handler(pkt):
  ssid = pkt[Dot11Elt].info
  bssid = pkt[Dot11].addr3
  channel = int( ord(pkt[Dot11Elt:3].info))

# fix this
#  if ssid_matches_patterns("", ssid):
#   print "[+] found matching SSID: %s" % ssid

  if not bssid in aps:
    aps.append(bssid)
    print "[+] CH: %i BSSID: %s - %s" % (channel, bssid, ssid)


def start_sniffing():
  iface = config["mon_iface"]
  sniff(iface=iface, filter="type mgt and subtype beacon", store=False, prn=packet_handler)


def handle_sigint(signum, frame):
  global stopper
  global t_chopper

  stopper.set()

  if t_chopper and t_chopper.is_alive():
    t_chopper.join()

  sys.exit("[!] exiting")

def main(args):
  global stopper
  global t_chopper

  parse_config(args.config)
  t_chopper = threading.Thread(target=channel_hopper)
  stopper = threading.Event()
  signal.signal(signal.SIGINT, handle_sigint)

  try:
    set_monitoring_mode()
    t_chopper.start()
    start_sniffing()
  finally:
    remove_monitoring_device()


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
