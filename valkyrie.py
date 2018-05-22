#!/usr/bin/python


from multiprocessing import Process
import xml.etree.ElementTree as et
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import logging
import os
import socket
import shelve
import panLogParse

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger('valkyrie')
formatter = logging.Formatter('%(asctime)s  %(module)s:%(levelname)s:%(funcName)s:\t%(message)s')
file_handler = logging.FileHandler('/var/log/pan/valkyrie.log')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)





if os.path.isfile('/etc/valkyrie/valkyrie.conf'):
    l_file = open('/etc/valkyrie/valkyrie.conf')
    for line in l_file:
        line = line.strip('\n')
        line = line.split(':')
        if line[0] == "LEVEL":
            logging_level = line[1]
    if logging_level == "DEBUG":
        logger.setLevel(logging.DEBUG)
    elif logging_level == "INFO":
        logger.setLevel(logging.INFO)
    elif logging_level == "WARNING":
        logger.setLevel(logging.WARNING)
    elif logging_level == "ERROR":
        logger.setLevel(logging.ERROR)
    elif logging_level == "CRITICAL":
        logger.setLevel(logging.CRITICAL)
    else:
        logger.critical("Invalid log level option. Setting log level to ERROR.")
        exit(1)
    l_file.close()
else:
    logger.setLevel(logging.ERROR)



def setQDict():
    query_dict = {}
    query_num = 1
    if os.path.isfile('/etc/valkyrie/valkyrie.conf'):
        o_file = open('/etc/valkyrie/valkyrie.conf')
        for line in o_file:
            line = line.strip('\n')
            line = line.split(':')
            if line[0] == "LEVEL":
                pass
            elif line[0] in ['traffic', 'threat', 'url', 'wildfire']:
                query_dict[query_num] = {'logtype' : line[0], 'query' : line[1] , 'destination' : line[2]}
                if query_dict[query_num]['query'] == "":
                    logger.warning('Sending an open query may result in an inability to keep up with log generation'
                                   ' rates.')
                query_num += 1
            else:
                logger.critical('Invalid log type: {}. Log type needs to be one of the following\n'.format(line[0])
                                + 'TRAFFIC\nTHREAT\nURL\nWILDFIRE\n'
                                + 'Please modify /etc/valkyrie/valkyrie.conf. Exiting.')
                exit(1)
    else:
        logger.critical('Configuration file not found. Please check /etc/valkyrie')
        exit(1)
    o_file.close()
    return query_dict


def fetchAPIKey():
    if os.path.isfile('/etc/valkyrie/data'):
        d_dict = {}
        s_data = shelve.open('/etc/valkyrie/data')
        api_key = s_data['api_key']
        pano_ip = s_data['pano_ip']
        d_dict['api_key'] = api_key
        d_dict['pano_ip'] = pano_ip
        return d_dict



def logWorker(pano_dict, query_dict, query_id):
    """Worker process for servicing log/query combo"""
    w_logger = logging.getLogger('query_{}'.format(query_id))
    w_logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler('/var/log/pan/q_{}.log'.format(query_id))
    formatter = logging.Formatter('%(asctime)s %(name)s\t%(levelname)s:\t\t%(message)s')
    fh.setFormatter(formatter)
    w_logger.addHandler(fh)


    last_seqno = 0
    if query_dict['query'] == "":
        query_params = {'type': 'log',
                        'log-type': query_dict['logtype'],
                        'nlogs': '5000',
                        'key': pano_dict['api_key']}
    else:
        query_params = {'type' : 'log',
                        'log-type' : query_dict['logtype'],
                        'nlogs' : '5000',
                        'query' : query_dict['query'],
                        'key' : pano_dict['api_key']}
    log_req = requests.get('https://{}/api/?'.format(pano_dict['pano_ip']), params=query_params, verify=False)
    w_logger.debug(log_req.url)
    w_logger.debug(log_req.content)
    log_xml = et.fromstring(log_req.content)
    job_id = log_xml.find('./result/job').text
    j_status = jobChecker(pano_dict, job_id)
    logs = fetchLogs(pano_dict, job_id)
    if logs == None:
        pass
    else:
        for log in logs:
            this_seqno = log.find('seqno').text
            if this_seqno > last_seqno:
                last_seqno = this_seqno
        parsend_worker = Process(target=parsend, args=(logs, query_dict['logtype']))
        parsend_worker.start()
    while True:
        current_query = query_dict['query'] + " and seqno gt " + str(last_seqno)
        query_params = {'type' : 'log',
                        'log-type' : query_dict['logtype'].lower,
                        'nlogs' : '5000',
                        'query' : current_query,
                        'key' : pano_dict['api_key']}
        log_req = requests.get('https://{}/api/?'.format(pano_dict['pano_ip'], params=query_params, verify=False))
        w_logger.debug(log_req.content)
        log_xml = et.fromstring(log_req.content)
        job_id = log_xml.find('./result/job').text
        j_status = jobChecker(pano_dict, job_id)
        logs = fetchLogs(pano_dict, job_id)
        if logs == None:
            pass
        else:
            for log in logs:
                this_seqno = log.find('seqno').text
                if this_seqno > last_seqno:
                    last_seqno = this_seqno
            parsend_worker = Process(target=parsend, args=(logs, query_dict))
            parsend_worker.start()






def fetchLogs(pano_dict, job_id):
    """Fetches the results of the indicated query job and returns a list of log objects in XML format"""
    fetch_params = {'type' : 'op',
                    'cmd' : '<show><query><result><id>{}</id></result></query></show>'.format(job_id),
                    'key' : pano_dict['api_key']}
    fetch_req = requests.get('https://{}/api/?'.format(pano_dict['pano_ip']), params=fetch_params, verify=False)
    fetch_xml = et.fromstring(fetch_req.content)
    count_node = fetch_xml.find('./result/log/logs')
    log_count = count_node.attrib['count']
    if log_count == "0":
        return None
    log_list = fetch_xml.findall('./result/log/logs/*')
    return log_list




def jobChecker(pano_dict, job_id):
    """Checks status of a given query job"""
    status = 'UNK'
    while status != "FIN":
        status_params = {'type' : 'op',
                      'cmd' : '<show><query><jobs></jobs></query></show>',
                      'key' : pano_dict['api_key']}
        status_req = requests.get('https://{}/api/?'.format(pano_dict['pano_ip']), params=status_params, verify=False)
        status_xml = et.fromstring(status_req.content)
        job_list = status_xml.findall('./result/*')
        for job in job_list:
            id = job.find('id').text
            if id == job_id:
                status = job.find('status')
    return 0


def parsend(log_list, q_dict):
    """Worker process for parsing logs from XML to specified format and sending to Syslog server"""
    syslog = logging.getLogger('syslog_sender')
    syslog.setLevel(logging.DEBUG)
    handler = logging.handlers.SyslogHandler(address=(q_dict['destination'], 514), facility='user')
    syslog.addHandler(handler)
    if q_dict['logtype'] == "traffic":
        logs = panLogParse.parseTraffic(log_list)
        for log in logs:
            syslog.debug(log)
    elif q_dict['logtype'] == "threat":
        logs = panLogParse.parseThreat(log_list)
        for log in logs:
            syslog.debug(log)
    elif q_dict['logtype'] == "url":
        logs = panLogParse.parseURL(log_list)
        for log in logs:
            syslog.debug(log)
    elif q_dict['logtype'] == "wildfire":
        logs = panLogParse.parseWF(log_list)
        for log in logs:
            syslog.debug(log)
    return



def main():
    q_dict = setQDict()
    pano_dict = fetchAPIKey()
    for query_id in q_dict:
        worker_proc = Process(target=logWorker, args=(pano_dict, q_dict[query_id], query_id))
        worker_proc.start()









if __name__ == '__main__':
    main()