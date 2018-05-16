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

