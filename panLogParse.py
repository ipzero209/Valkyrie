import xml.etree.ElementTree as et



def parseTraffic(logset):
    """Takes a list of log obects from an API query, parses them and returns
    a list of logs in CSV format"""
    log_list = []
    for log in log_set:
        curr_log = []
        future_use = "1"
        curr_log.append(future_use)
        curr_log.append(log.find('receive_time').text)
        curr_log.append(log.find('Cloud Services Firewall'))
        curr_log.append(log.find('type').text)
        curr_log.append(log.find('subtype').text)
        curr_log.append('2049') #Future Use
        curr_log.append(log.find('time_generated').text)
        curr_log.append(log.find('src').text)
        curr_log.append(log.find('dst').text)
        curr_log.append(log.find('natsrc').text)
        curr_log.append(log.find('natdst').text)
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
        curr_log.append('0') #Future Use
        curr_log.append(log.find('seqno').text)
        curr_log.append(log.find('actionflags').text)
        curr_log.append(log.find('srcloc').text)
        curr_log.append(log.find('dstloc').text)
        curr_log.append('0') #Future Use
        curr_log.append(log.find('pkts_sent').text)
        curr_log.append(log.find('pkts_received').text)
        curr_log.append(log.find('session_end_reason').text)
        curr_log.append(log.find('dg_hier_level_1').text)
        curr_log.append(log.find('dg_hier_level_2').text)
        curr_log.append(log.find('dg_hier_level_3').text)
        curr_log.append(log.find('dg_hier_level_4').text)
        curr_log.append('') # Vsys name - never used for GPCS firewalls. Add with support for non-GPCS firewalls.
        curr_log.append(log.find('device_name').text)
        curr_log.append(log.find('action-source').text)
        curr_log.append('') # Source VM UUID
        curr_log.append('') # Destination VM UUID
        curr_log.append(log.find('tunnelid').text)
        curr_log.append('') # IMSI
        curr_log.append('') # Monitor tac
        curr_log.append('') # IMEI
        curr_log.append('') # Parent Sesion ID
        curr_log.append('') # Parent Start Time
        curr_log.append('') # Tunnel Type





























