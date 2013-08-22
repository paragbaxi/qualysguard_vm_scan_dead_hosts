#!/usr/bin/python

# By Parag Baxi <parag.baxi@gmail.com>
# License GPL v3

import sys
from lxml import objectify
import netaddr, logging

def ip_range_expand(ip_range):
    """Return list of ip addresses from ip_range.
       Example:
       >>> ip_range_expand(['10.0.0.0/31', '10.0.0.3/32'])
       ['10.0.0.0', '10.0.0.1', '10.0.0.3']
       """
    ip_range_expanded = []
    for cidr_object in ip_range:
        # Expand each CIDR.
        for ip_addy in netaddr.IPNetwork(cidr_object):
            # Add individual IP to expansion range.
            ip_range_expanded.append(str(ip_addy))
    return unique(ip_range_expanded)

def unique(seq):
    """Return seq list after removing duplicates whilst preserving order."""
    seen = set()
    seen_add = seen.add
    return [ x for x in seq if x not in seen and not seen_add(x)]

def ip_range_diff(source_ip_range, remove_ip_range):
    """Return source_ip_range after excluding remove_ip_range."""
    # Convert IP ranges to CIDR.
    source_ip_range = ip_range_to_cidr(source_ip_range)
    remove_ip_range = ip_range_to_cidr(remove_ip_range)
    logging.debug('source_ip_range = %s' % (source_ip_range))
    logging.debug('remove_ip_range = %s' % (remove_ip_range))
    # Expand each range.
    source_ip_range_expanded = ip_range_expand(source_ip_range)
    remove_ip_range_expanded = ip_range_expand(remove_ip_range)
#    logging.debug('remove_ip_range_expanded = %s' % (remove_ip_range_expanded))
    # Remove each matching source IP address individually.
    for i in remove_ip_range_expanded:
        try:
            source_ip_range_expanded.remove(i)
        except ValueError:
            # Value not in source_ip_range
            continue
    # Convert remaining range to CIDR.
#    logging.debug('source_ip_range_expanded = %s' % (source_ip_range_expanded))
    source_ip_range = netaddr.cidr_merge(source_ip_range_expanded)
    logging.debug('source_ip_range = %s' % (source_ip_range))
    # Convert each CIDR block to string.
    result_cidr = []
    for cidr_object in source_ip_range:
        result_cidr.append(str(cidr_object))
    # Convert entire list to a string.
    result_cidr = ','.join(result_cidr)
    logging.debug('result_cidr = %s' % (result_cidr))
    # Remove '/32' (single IP) and return diff'd range.
    return result_cidr.replace('/32', '')

def ip_range_to_cidr(ip_network_string):
    """Convert ip_network_string into CIDR notation."""
    # Split string into list by ', ' delimiter.
    ip_network_cidr = []
    ip_network_list = ip_network_string.split(',')
    for ip_object in ip_network_list:
        # For every ip range ('10.182.71.0-10.182.75.255'), convert to individual slash notation, 10.182.71.0/24, 10.182.72.0/22.
        if '-' in ip_object:
            # The object is a range.
            dash = ip_object.find('-')
            # First part of ip range.
            ip_start = ip_object[:dash]
            # Last part of ip range.
            ip_end = ip_object[dash + 1:]
            # Generate lists of IP addresses in range.
            ip_range = list(netaddr.iter_iprange(ip_start, ip_end))
            # Convert start & finish range to CIDR.
            ip_range = netaddr.cidr_merge(ip_range)
            # May be one or more objects in list.
            # Example 1:  '10.182.71.0-10.182.75.255' ==> ['10.182.71.0/24, 10.182.72.0/22']
            # Example 2:  '10.182.90.0-10.182.91.255' ==> ['10.182.90.0/23']
            # Add each CIDR to ip_network.
            for ip_object in ip_range:
                 ip_network_cidr.append(str(ip_object))
        else:
            # The object is not a range, just add it.
            logging.debug('ip_object = %s' % (ip_object))
            ip_network_cidr.append(str(netaddr.IPNetwork(ip_object).cidr))
    # Return as a string with delimiter ', '
    return ip_network_cidr


def glob_to_ip_range(globs):
    """Convert string of globs to a string of ip ranges in CIDR format.

       Example:
       >>> glob_to_ip_range('10.0.0.0/23')
       '10.0.0.0/24, 10.0.1.0/24'
       >>> glob_to_ip_range('10.108.0.0/16')
       '10.108.0.0/16'

       """
    globs = globs.split(',')
    ip_ranges = ''
    for i in globs:
        logging.debug('i = %s' % (i))
        try:
            i = netaddr.glob_to_cidrs(i)
            for j in i:
                ip_ranges += '%s, ' % (str(j))
        except ValueError, e:
            # Not a glob.
            logging.debug('ValueError: %s' % (e))
            ip_ranges += '%s, ' % (i)
        except netaddr.core.AddrFormatError, e:
            logging.debug(e)
            i = ip_range_to_cidr(i)
            for j in i:
                ip_ranges += '%s, ' % (str(j))
    ip_ranges = ip_ranges[:-2]
    logging.debug('ip_ranges = %s' % (ip_ranges))
    return ip_ranges

xml_file = sys.argv[1]
with open(xml_file, 'r') as report_xml_file:
    root = objectify.parse(report_xml_file).getroot()

ips_targets = root.HEADER.xpath('//KEY[@value="TARGET"]/text()')[0]
print 'IP targets:\n', ips_targets, '\n'
ips_discovered_list = []
for ip_discovered in root.IP:
    ips_discovered_list.append(ip_discovered.get('value'))
ips_discovered = ','.join([str(ip) for ip in ips_discovered_list])

print 'IPs scanned:\n', ips_discovered, '\n'

print 'IPs not scanned:\n', ip_range_diff(ips_targets,ips_discovered)
