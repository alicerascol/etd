# Evil Twin Detector

Monitor for Evil Twin access points and be alerted of their presence

## Approach

The monitor will put the WLAN device specified into monitor mode and will scan for beacon frames being broadcast, at the same
it will periodically hop channels, it then compares the bssid & ssid against a configured whitelist and any found that do not
match will then be recorded and an alert sent.

