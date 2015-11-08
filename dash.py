from scapy.all import *
import requests
import time
MAGIC_FORM_URL = 'http://api.cloudstitch.com/user/magic-form/datasources/sheet'

def record(activity):
  try:
    data = {
      "Timestamp": time.strftime("%Y-%m-%d %H:%M"), 
      "Measurement": activity
    }
    requests.post(MAGIC_FORM_URL, data)
  except: 
    print "Com failure"

def arp_display(pkt):
  timestamp = time.strftime("%Y-%m-%d %H:%M")
  try:
    if pkt[ARP].op == 1: #who-has (request)
      if pkt[ARP].psrc == '0.0.0.0': # ARP Probe
        if pkt[ARP].hwsrc == 'a0:02:dc:10:29:ba': # Gillete        
          print "Pushed Gillete Dash"
          record("Got home")
        elif pkt[ARP].hwsrc == '74:75:48:8f:50:6a': # Elements 1
          print "Pushed Elements Dash"
          record("Worked out")
        elif pkt[ARP].hwsrc == '70:ee:50:05:57:6c': # Unknown device
          pass
        else:
          print "ARP Probe from unknown device: " + pkt[ARP].hwsrc
  except: 
    print "Error"      

print sniff(prn=arp_display, filter="arp", store=0, count=0)