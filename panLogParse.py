import xml.etree.ElementTree as et



def parseTraffic(logset):
    """Takes a list of log traffic obects from an API query, parses them and returns
    a list of logs in CSV format."""
    log_list = []
    for log in logset:
        curr_log = []
        future_use = "1"
        curr_log.append('1') # Future Use
        curr_log.append(log.find('receive_time').text)
        serial = log.find('serial')
        if serial == None:
            curr_log.append('')
        else:
            curr_log.append(serial.text)
        # curr_log.append(log.find('Cloud Services Firewall'))
        curr_log.append(log.find('type').text)
        curr_log.append(log.find('subtype').text)
        curr_log.append('2049') # Future Use
        curr_log.append(log.find('time_generated').text)
        curr_log.append(log.find('src').text)
        curr_log.append(log.find('dst').text)
        natsrc = log.find('natsrc')
        if natsrc == None:
            curr_log.append('')
        else:
            curr_log.append(natsrc.text)
        natdst = log.find('natdst')
        if natdst == None:
            curr_log.append('')
        else:
            curr_log.append(natdst.text)
        curr_log.append(log.find('rule').text)
        srcuser = log.find('srcuser')
        if srcuser == None:
            curr_log.append('')
        else:
            curr_log.append(srcuser.text)
        dstuser = log.find('dstuser')
        if dstuser == None:
            curr_log.append('')
        else:
            curr_log.append(log.find('dstuser.text'))
        curr_log.append(log.find('app').text)
        curr_log.append(log.find('vsys_id').text)
        curr_log.append(log.find('from').text)
        curr_log.append(log.find('to').text)
        curr_log.append(log.find('inbound_if').text)
        curr_log.append(log.find('outbound_if').text)
        curr_log.append(log.find('logset').text)
        curr_log.append(log.find('time_generated').text) #Future Use
        curr_log.append(log.find('sessionid').text)
        curr_log.append(log.find('repeatcnt').text)
        curr_log.append(log.find('sport').text)
        curr_log.append(log.find('dport').text)
        curr_log.append(log.find('natsport').text)
        curr_log.append(log.find('natdport').text)
        curr_log.append(log.find('flags').text)
        curr_log.append(log.find('proto').text)
        curr_log.append(log.find('action').text)
        curr_log.append(log.find('bytes').text)
        curr_log.append(log.find('bytes_sent').text)
        curr_log.append(log.find('bytes_received').text)
        curr_log.append(log.find('packets').text)
        curr_log.append(log.find('start').text)
        curr_log.append(log.find('elapsed').text)
        curr_log.append(log.find('category').text)
        curr_log.append('0') # Future Use
        curr_log.append(log.find('seqno').text)
        curr_log.append(log.find('actionflags').text)
        curr_log.append(log.find('srcloc').text)
        curr_log.append(log.find('dstloc').text)
        curr_log.append('0') #F uture Use
        curr_log.append(log.find('pkts_sent').text)
        curr_log.append(log.find('pkts_received').text)
        curr_log.append(log.find('session_end_reason').text)
        curr_log.append(log.find('dg_hier_level_1').text)
        curr_log.append(log.find('dg_hier_level_2').text)
        curr_log.append(log.find('dg_hier_level_3').text)
        curr_log.append(log.find('dg_hier_level_4').text)
        curr_log.append('') # Vsys name - never used for GPCS firewalls. Add with support for non-GPCS firewalls.
        curr_log.append(log.find('device_name').text)
        curr_log.append(log.find('action_source').text)
        curr_log.append('') # Source VM UUID
        curr_log.append('') # Destination VM UUID
        curr_log.append(log.find('tunnelid').text)
        curr_log.append('') # IMSI
        curr_log.append('') # Monitor tag
        curr_log.append('') # IMEI
        curr_log.append('') # Parent Session ID
        curr_log.append('') # Parent Start Time
        curr_log.append('') # Tunnel Type
        curr_log_string = ",".join(curr_log)
        log_list.append(curr_log_string)
    return log_list

def parseThreat(logset):
    """Takes a list of log traffic objects from an API query, parses them and returns
    a list of logs in CSV format"""
    log_list = []
    for log in logset:
        curr_log = []
        curr_log.append('1') # Future Use
        curr_log.append(log.find('receive_time').text)
        serial = log.find('serial')
        if serial == None:
            curr_log.append('')
        else:
            curr_log.append(serial.text)
        curr_log.append(log.find('type').text)
        curr_log.append(log.find('subtype').text)
        curr_log.append('2049') # Future Use
        curr_log.append(log.find('time_generated').text)
        curr_log.append(log.find('src').text)
        curr_log.append(log.find('dst').text)
        natsrc = log.find('natsrc')
        if natsrc == None:
            curr_log.append('0.0.0.0')
        else:
            curr_log.append(natsrc.text)
        natdst = log.find('netdst')
        if natdst == None:
            curr_log.append('0.0.0.0')
        else:
            curr_log.append(natdst.text)
        curr_log.append(log.find('rule').text)
        srcuser = log.find('srcuser')
        if srcuser == None:
            curr_log.append('')
        else:
            curr_log.append(srcuser.text)
        dstuser = log.find('dstuser')
        if dstuser == None:
            curr_log.append('')
        else:
            curr_log.append(dstuser.text)
        curr_log.append(log.find('app').text)
        curr_log.append(log.find('vsys_id').text)
        curr_log.append(log.find('from').text)
        curr_log.append(log.find('to').text)
        curr_log.append(log.find('inbound_if').text)
        curr_log.append(log.find('outbound_if').text)
        curr_log.append(log.find('logset').text)
        curr_log.append(log.find('time_generated').text) # Future Use
        curr_log.append(log.find('sessionid').text)
        curr_log.append(log.find('repeatcnt').text)
        curr_log.append(log.find('sport').text)
        curr_log.append(log.find('dport').text)
        natsport = log.find('natsport')
        if natsport == None:
            curr_log.append('0')
        else:
            curr_log.append(natsport.text)
        natdport = log.find('natdport')
        if natdport == None:
            curr_log.append('0')
        else:
            curr_log.append(natdport.text)
        curr_log.append(log.find('flags').text)
        curr_log.append(log.find('proto').text)
        curr_log.append(log.find('action').text)
        misc = log.find('misc')
        if misc == None:
            curr_log.append('')
        else:
            curr_log.append(misc.text)
        curr_log.append(log.find('threatid').text)
        curr_log.append(log.find('category').text)
        curr_log.append(log.find('severity').text)
        curr_log.append(log.find('direction').text)
        curr_log.append(log.find('seqno').text)
        curr_log.append(log.find('actionflags').text)
        curr_log.append(log.find('srcloc').text)
        curr_log.append(log.find('dstloc').text)
        curr_log.append('0') # Future Use
        curr_log.append('') # Content Type
        curr_log.append(log.find('pcap_id').text)
        curr_log.append('') # File Digest - only used for WF subtype
        curr_log.append('') # Cloud - only used for WF subtype
        curr_log.append(log.find('url_idx').text) # Only used for URL and WF subtypes
        curr_log.append('') # User Agent - only used for URL subtype
        curr_log.append('') # File Type - only used for WF subtype
        curr_log.append('') # X-FWD-FOR - only used for URL subtype
        curr_log.append('') # Referer - only used for URL subtype
        curr_log.append('') # Sender - only used for WF subtype
        curr_log.append('') # Subject - only used for WF subtype
        curr_log.append('') # Recipient - only used for WF subtype
        curr_log.append('') # Report ID - only used for WF subtype
        curr_log.append(log.find('dg_hier_level_1').text)
        curr_log.append(log.find('dg_hier_level_2').text)
        curr_log.append(log.find('dg_hier_level_3').text)
        curr_log.append(log.find('dg_hier_level_4').text)
        curr_log.append(log.find('vsys_name').text)
        curr_log.append(log.find('device_name').text)
        curr_log.append('') # Future Use
        curr_log.append('') # Source VM UUID
        curr_log.append('') # Destination VM UUID
        curr_log.append('') # HTTP Method - only used for URL subtype
        curr_log.append(log.find('tunnelid_imsi').text)
        curr_log.append('') # IMEI
        curr_log.append('') # Parent Session ID
        curr_log.append('') # Parent Start Time
        curr_log.append('') # Tunnel Type
        curr_log.append(log.find('thr_category').text)
        curr_log.append(log.find('contentver').text)
        curr_log.append('0x0') # Future Use
        curr_log.append('') # SCTP Association ID
        curr_log.append(log.find('ppid').text)
        curr_log.append('') # HTTP Headers - only used for URL subtype
        curr_log_str = ",".join(curr_log)
        log_list.append(curr_log_str)
    return log_list



def parseURL(logset):
    """Takes a list of log traffic objects from an API query, parses them and returns
    a list of logs in CSV format"""
    log_list = []
    for log in logset:
        curr_log = []
        curr_log.append('1') # Future Use
        curr_log.append(log.find('receive_time').text)
        serial = log.find('serial')
        if serial == None:
            curr_log.append('')
        else:
            curr_log.append(serial.text)
        curr_log.append(log.find('type').text)
        curr_log.append(log.find('subtype').text)
        curr_log.append('2049') # Future Use
        curr_log.append(log.find('time_generated').text)
        curr_log.append(log.find('src').text)
        curr_log.append(log.find('src').text)
        curr_log.append(log.find('dst').text)
        natsrc = log.find('natsrc')
        if natsrc == None:
            curr_log.append('0.0.0.0')
        else:
            curr_log.append(natsrc.text)
        natdst = log.find('netdst')
        if natdst == None:
            curr_log.append('0.0.0.0')
        else:
            curr_log.append(natdst.text)
        curr_log.append(log.find('rule').text)
        srcuser = log.find('srcuser')
        if srcuser == None:
            curr_log.append('')
        else:
            curr_log.append(srcuser.text)
        dstuser = log.find('dstuser')
        if dstuser == None:
            curr_log.append('')
        else:
            curr_log.append(dstuser.text)
        curr_log.append(log.find('app').text)
        curr_log.append(log.find('vsys_id').text)
        curr_log.append(log.find('from').text)
        curr_log.append(log.find('to').text)
        curr_log.append(log.find('inbound_if').text)
        curr_log.append(log.find('outbound_if').text)
        curr_log.append(log.find('logset').text)
        curr_log.append(log.find('time_generated').text) # Future Use
        curr_log.append(log.find('sessionid').text)
        curr_log.append(log.find('repeatcnt').text)
        curr_log.append(log.find('sport').text)
        curr_log.append(log.find('dport').text)
        natsport = log.find('natsport')
        if natsport == None:
            curr_log.append('0')
        else:
            curr_log.append(natsport.text)
        natdport = log.find('natdport')
        if natdport == None:
            curr_log.append('0')
        else:
            curr_log.append(natdport.text)
        curr_log.append(log.find('flags').text)
        curr_log.append(log.find('proto').text)
        curr_log.append(log.find('action').text)
        misc = log.find('misc')
        if misc == None:
            curr_log.append('')
        else:
            curr_log.append(misc.text)
        # curr_log.append(log.find('threatid').text)
        curr_log.append(log.find('category').text)
        curr_log.append(log.find('severity').text)
        curr_log.append(log.find('direction').text)
        curr_log.append(log.find('seqno').text)
        curr_log.append(log.find('actionflags').text)
        curr_log.append(log.find('srcloc').text)
        curr_log.append(log.find('dstloc').text)
        curr_log.append('0') # Future Use
        curr_log.append('') # Content Type
        curr_log.append(log.find('pcap_id').text)
        curr_log.append('') # File Digest - only used for WF subtype
        curr_log.append('') # Cloud - only used for WF subtype
        curr_log.append(log.find('url_idx').text) # Only used for URL and WF subtypes
        curr_log.append('') # User Agent - only used for URL subtype
        curr_log.append('') # File Type - only used for WF subtype
        curr_log.append('') # X-FWD-FOR - only used for URL subtype
        curr_log.append('') # Referer - only used for URL subtype
        curr_log.append('') # Sender - only used for WF subtype
        curr_log.append('') # Subject - only used for WF subtype
        curr_log.append('') # Recipient - only used for WF subtype
        curr_log.append('') # Report ID - only used for WF subtype
        curr_log.append(log.find('dg_hier_level_1').text)
        curr_log.append(log.find('dg_hier_level_2').text)
        curr_log.append(log.find('dg_hier_level_3').text)
        curr_log.append(log.find('dg_hier_level_4').text)
        curr_log.append(log.find('vsys_name').text)
        curr_log.append(log.find('device_name').text)
        curr_log.append('') # Future Use
        curr_log.append('') # Source VM UUID
        curr_log.append('') # Destination VM UUID
        curr_log.append('') # HTTP Method - only used for URL subtype
        curr_log.append(log.find('tunnelid_imsi').text)
        curr_log.append('') # IMEI
        curr_log.append('') # Parent Session ID
        curr_log.append('') # Parent Start Time
        curr_log.append('') # Tunnel Type
        curr_log.append(log.find('thr_category').text)
        curr_log.append(log.find('contentver').text)
        curr_log.append('0x0') # Future Use
        curr_log.append('') # SCTP Association ID
        curr_log.append(log.find('ppid').text)
        curr_log.append('') # HTTP Headers - only used for URL subtype
        curr_log_str = ",".join(curr_log)
        log_list.append(curr_log_str)
    return log_list


def parseWF(logset):
    """Takes a list of log traffic objects from an API query, parses them and returns
    a list of logs in CSV format"""
    log_list = []
    for log in logset:
        curr_log = []
        curr_log.append('1') # Future Use
        curr_log.append(log.find('receive_time').text)
        serial = log.find('serial')
        if serial == None:
            curr_log.append('')
        else:
            curr_log.append(serial.text)
        curr_log.append(log.find('type').text)
        curr_log.append(log.find('subtype').text)
        curr_log.append('2049') # Future Use
        curr_log.append(log.find('time_generated').text)
        curr_log.append(log.find('src').text)
        curr_log.append(log.find('src').text)
        curr_log.append(log.find('dst').text)
        natsrc = log.find('natsrc')
        if natsrc == None:
            curr_log.append('0.0.0.0')
        else:
            curr_log.append(natsrc.text)
        natdst = log.find('netdst')
        if natdst == None:
            curr_log.append('0.0.0.0')
        else:
            curr_log.append(natdst.text)
        curr_log.append(log.find('rule').text)
        srcuser = log.find('srcuser')
        if srcuser == None:
            curr_log.append('')
        else:
            curr_log.append(srcuser.text)
        dstuser = log.find('dstuser')
        if dstuser == None:
            curr_log.append('')
        else:
            curr_log.append(dstuser.text)
        curr_log.append(log.find('app').text)
        curr_log.append(log.find('vsys_id').text)
        curr_log.append(log.find('from').text)
        curr_log.append(log.find('to').text)
        curr_log.append(log.find('inbound_if').text)
        curr_log.append(log.find('outbound_if').text)
        curr_log.append(log.find('logset').text)
        curr_log.append(log.find('time_generated').text) # Future Use
        curr_log.append(log.find('sessionid').text)
        curr_log.append(log.find('repeatcnt').text)
        curr_log.append(log.find('sport').text)
        curr_log.append(log.find('dport').text)
        natsport = log.find('natsport')
        if natsport == None:
            curr_log.append('0')
        else:
            curr_log.append(natsport.text)
        natdport = log.find('natdport')
        if natdport == None:
            curr_log.append('0')
        else:
            curr_log.append(natdport.text)
        curr_log.append(log.find('flags').text)
        curr_log.append(log.find('proto').text)
        curr_log.append(log.find('action').text)
        misc = log.find('misc')
        if misc == None:
            curr_log.append('')
        else:
            curr_log.append(misc.text)
        curr_log.append(log.find('threatid').text)
        curr_log.append(log.find('category').text)
        curr_log.append(log.find('severity').text)
        curr_log.append(log.find('direction').text)
        curr_log.append(log.find('seqno').text)
        curr_log.append(log.find('actionflags').text)
        curr_log.append(log.find('srcloc').text)
        curr_log.append(log.find('dstlog').text)
        curr_log.append('0') # Future Use
        curr_log.append('') # Content Type
        curr_log.append(log.find('pcap_id').text)
        curr_log.append(log.find('filedigest').text) # File Digest - only used for WF subtype
        curr_log.append(log.find('cloud').text) # Cloud - only used for WF subtype
        curr_log.append(log.find('url_idx').text) # Only used for URL and WF subtypes
        curr_log.append('') # User Agent - only used for URL subtype
        curr_log.append(log.find('filetype').text) # File Type - only used for WF subtype
        curr_log.append('') # X-FWD-FOR - only used for URL subtype
        curr_log.append('') # Referer - only used for URL subtype
        curr_log.append(log.find('sender').text) # Sender - only used for WF subtype
        curr_log.append(log.find('subject').text) # Subject - only used for WF subtype
        curr_log.append(log.find('recipient').text) # Recipient - only used for WF subtype
        curr_log.append(log.find('reportid').text) # Report ID - only used for WF subtype
        curr_log.append(log.find('dg_hier_level_1').text)
        curr_log.append(log.find('dg_hier_level_2').text)
        curr_log.append(log.find('dg_hier_level_3').text)
        curr_log.append(log.find('dg_hier_level_4').text)
        curr_log.append(log.find('vsys_name').text)
        curr_log.append(log.find('device_name').text)
        curr_log.append('') # Future Use
        curr_log.append('') # Source VM UUID
        curr_log.append('') # Destination VM UUID
        curr_log.append('') # HTTP Method - only used for URL subtype
        curr_log.append(log.find('tunnelid_imsi').text)
        curr_log.append('') # IMEI
        curr_log.append('') # Parent Session ID
        curr_log.append('') # Parent Start Time
        curr_log.append('') # Tunnel Type
        curr_log.append(log.find('thr_category').text)
        curr_log.append(log.find('contentver').text)
        curr_log.append('0x0') # Future Use
        curr_log.append('') # SCTP Association ID
        curr_log.append(log.find('ppid').text)
        curr_log.append('') # HTTP Headers - only used for URL subtype
        curr_log_str = ",".join(curr_log)
        log_list.append(curr_log_str)
    return log_list



































