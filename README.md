qualysguard_vm_scan_dead_hosts
==============================

Print hosts targetted, scanned, and not scanned from manual scan XML.

So, for hosts not scanned, one just finds the delta between what QualysGuard was targeted to scan and actually scanned.
Targeted to scan = ROOT > HEADER > KEY (value=TARGET).
Successfully Scanned Hosts (IP): ROOT > IP. Iterate through all IP tags.

Example
=======
<pre>
$ python list_ips.py Scan_Results_subsc_usr1_20130821_scan_1377
093123_44396.xml
IP targets:
10.20.30.100,64.39.106.1,64.39.106.242-64.39.106.249 

IPs scanned:
10.20.30.100 

IPs not scanned:
64.39.106.1,64.39.106.242/31,64.39.106.244/30,64.39.106.248/31
</pre>
