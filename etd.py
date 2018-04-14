#!/usr/bin/env python
# coding=utf-8

import os
import sys
import time
import thread
import fnmatch
import ConfigParser
import scapy

from argparse import ArgumentParser



def main(args):
  pass


if __name__ == "__main__":
  parser = ArgumentParser(description="EvilTwin Detector tool - Mike Cromwell 2018")

  parser.add_argument("-v", "--verbose", help="add extra logging", type=bool, default=False)
  parser.add_argument("-c", "--config", help="use different config file", type=str, default="etd.conf")

  args = parser.parse_args()
  main(args)
