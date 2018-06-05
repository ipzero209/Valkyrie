#!/usr/bin/python

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import xml.etree.ElementTree as et
import getpass
import shelve
import os
import logging
import argparse
import sys



requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


if os.getuid() != 0:
    print "Not running with sudo. Please re-start setup using 'sudo ./v_setup.py'"
    exit(1)

if os.path.isdir('/var/log/pan'):
    pass
else:
    os.system('mkdir /var/log/pan')
    logger.info('Created log directory')
    os.system('chmod 777 /var/log/pan')

logger = logging.getLogger("setup")
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('/var/log/pan/v_setup.log')
formatter = logging.Formatter('%(asctime)s %(name)s\t%(levelname)s:\t\t%(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)



def getKey():
    """Used to fetch the API for for Panorama"""
    pano_ip = raw_input("Enter the IP address of your Panorama: ")
    user = raw_input("Enter the API username: ")
    passwd = getpass.getpass("\nEnter the password for the API user: ")
    pano_status = upCheck(pano_ip)
    if pano_status != 0:
        path = os.popen('tracepath -l 1460 {}'.format(pano_ip)).read()
        logger.critical('Cannot ping Panorama. Path (using pktlen=1460) is:\n\n{}'.format(path))
        print "Cannot ping Panorama. Path (using pktlen=1460) is:\n\n{}".format(path)
    key_params = {'type' : 'keygen',
                  'user' : user,
                  'password' : passwd}
    try:
        key_req = requests.get('https://{}/api/?'.format(pano_ip), params=key_params, verify=False)
    except Exception as e:
        logger.critical("Unable to reach Panorama on TCP/443. Error is: \n\n{}".format(e))
        print "Unable to reach Panorama on TCP/443. Error is:\n\n{}".format(e)
    key_xml = et.fromstring(key_req.content)
    if key_req.status_code != 200:
        err_node = key_xml.find('./result/msg')
        logger.critical('Error retrieving API key from {}:\n{}'.format(pano_ip, err_node.text))
        return 1
    key_node = key_xml.find('./result/key')
    logger.info('API key successfully retrieved from {}.'.format(pano_ip))
    saveInfo('pano_ip', pano_ip)
    saveInfo('api_key', key_node.text)
    return 0


def saveInfo(key_str, data):
    """Used shelve data for subsequent use"""
    logger.info('Saving {}.'.format(key_str))
    s_data = shelve.open('/etc/valkyrie/data')
    s_data[key_str] = data
    s_data.close()
    logger.info('Setting permissions on data file')
    conf_perm = os.system('chmod 766 /etc/valkyrie/data')
    logger.info('{} saved to data file'.format(key_str))
    return




def upCheck(ip_addr):
    """Checks for basic connectivity to Panorama"""
    status = os.system('ping -c 1 {}'.format(ip_addr))
    return status



def prepService():
    """Moves files to the appropriate directories and sets the correct permissions"""
    logger.info('Copying valkyrie to /etc/init.d')
    v_cp = os.system('cp ./valkyrie /etc/init.d/')
    if v_cp != 0:
        logger.critical('Could not copy valkyrie to /etc/init.d. Are we running with sudo?')
        return 1
    logger.info('Setting permissions on valkyrie.')
    v_perm = os.system('chmod 755 /etc/init.d/valkyrie')
    if v_perm != 0:
        logger.critical('Failed to set permissions on /etc/init.d/valkyrie')
        return 1
    logger.info('Copying configuration file to /etc/valkyrie/valkyrie')
    cp_conf = os.system('cp ./valkyrie.conf /etc/valkyrie/valkyrie.conf')
    if cp_conf != 0:
        logger.critical('Failed to copy configuration file')
    logger.info('Setting permissions on configuration file')
    conf_perm = os.system('chmod 755 /etc/valkyrie/valkyrie.conf')
    if conf_perm != 0:
        logger.critical('Failed to set permissions on configuration file')
    py_list = ['valkyrie.py', 'v_setup.py', 'panLogParse.py']
    for file in py_list:
        logger.info('Copying {} to /usr/local/bin'.format(file))
        py_copy = os.system('cp ./{} /usr/local/bin'.format(file))
        if py_copy != 0:
            logger.critical('Failed to copy {} to /usr/local/bin'.format(file))
            return 1
        logger.info('Setting permissions on /usr/local/bin/{}'.format(file))
        py_perm = os.system('chmod 755 /usr/local/bin/{}'.format(file))
        if py_perm != 0:
            logger.critical('Failed to set permissions on /usr/local/bin/{}'.format(file))
            return 1
    logger.info('Setting up valkyrie log file')
    log_touch = os.system('touch /var/log/pan/valkyrie.log')
    if log_touch != 0:
        logger.critical('Failed to create valkyrie log file')
    log_perm = os.system('chmod 766 /var/log/pan/valkyrie.log')
    if log_perm != 0:
        logger.critical('Failed to set permissions on valkyrie log file')
    logger.info('Updating rc.d')
    update_rc = os.system('update-rc.d valkyrie defaults')
    if update_rc != 0:
        logger.critical('Failed to update rc.d')
        return 1
    return 0


def svcStart():
    """Starts the service"""
    logger.info('Attempting to start the service')
    svc_start = os.system('service valkyrie start')
    if svc_start != 0:
        logger.critical('Failed to start valkyrie.')
        return 1
    svc_status = os.popen('service valkyrie status').read()
    if "(exited)" in svc_status:
        logger.critical('Valkyrie service exited. Please start the service manually using '
                        '\'sudo service valkyrie start\'.')
        print 'Valkyrie service exited. Please start the service manually using \'sudo ' \
              'service valkyrie start\'.'
        return 1
    elif "(running)" in svc_status:
        logger.info('Valkyrie service started successfully')
        return 0


def svcStop():
    """Stops the service"""
    logger.info('Attempting to stop the service')
    svc_stop = os.system('service valkyrie stop')
    if svc_stop != 0:
        logger.critical('Failed to stop valkyrie service')
        return 1
    return 0


def removeFiles():
    """Deletes Valkyrie related files"""
    os.system('rm -rf /etc/valkyrie')
    file_list = ['valkyrie.*', 'panLogParse.*', 'v_setup.*',]
    for file in file_list:
        os.system('rm -f /usr/local/bin/{}'.format(file))
    os.system('rm -f /etc/init.d/valkyrie')
    print "Manually delete log files located at /var/log/pan/ if desired."
    return

def main():

    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-i", "--install", help="Installs Valkyrie", action="store_true")
    group.add_argument("-r", "--renew", help="Updates the stored API key", action="store_true")
    group.add_argument("-u", "--uninstall", help="Uninstalls Valkyrie", action="store_true")
    args = parser.parse_args()
    if len(sys.argv) <2:
        parser.print_help()
        parser.exit()
        exit(1)

    if args.install:
        print "Welcome to Valkyrie. This setup will guide you through getting Valkyrie up and running."
        sys_dir = os.system('mkdir /etc/valkyrie')
        if sys_dir == 0:
            logger.info('Created system directory /etc/valkyrie')
        else:
            logger.error('Error creating system directory /etc/valkyrie. Exiting now.')
            exit(1)
        api_key = getKey()
        if api_key == 1:
            logger.critical('Error retrieving API key')
            exit(1)
        prep = prepService()
        if prep == 1:
            logger.critical('Critical error in service setup. Please see log for additional details.')
            print "Critical error in service setup. Please see log for additional details."
        s_start = svcStart()
        if s_start != 0:
            logger.critical('Critical error starting the service. Please see log for details.')
        logger.info('Setup complete')
        print "Setup Complete"
        exit(0)
    elif args.renew:
        if not os.path.isfile('/etc/valkyrie/data'):
            logger.info('No data file found. Please check the location of the '
                        'data file. The file name is \'data\' and it should  be '
                        'located at /etc/valkyrie/')
            print "Error opening the data file. Please see the setup log for details."
        stop = svcStop()
        if stop == 1:
            logger.critical('Failed to stop the service. Exiting now.')
            print "There was an error when attempting to stop the service."
            exit(1)
        k_status = getKey()
        if k_status != 0:
            logger.critical('There was an issue renewing the API key.')
            exit(1)
        start = svcStart()
        if start != 0:
            logger.warning('Error starting the service. Please start the service '
                           'manually.')
            print "There was an error when attempting to start the service. " \
                  "Please start the service manually"
        exit(0)
    elif args.uninstall:
        confirm = raw_input('This will uninstall Valkyrie from your system.\n'
                            'Are you sure? (y/N): ')
        if confirm == ('' or 'n' or 'N' or 'no' or 'No' or 'NO'):
            logger.info('Cancelling uninstall at user request.')
            exit(0)
        elif confirm == ('y' or 'Y' or 'Yes' or 'yes' or 'YES'):
            print "Proceding with uninstall."
            logger.warning('Uninstall confirmed by user')
            svcStop()
            removeFiles()
        else:
            print "Please enter y or n. Exiting now."
            logger.warning('Invalid choice for confirmation prompt. Exiting.')
            exit(0)
        stop = svcStop()
        if stop == 1:
            print "Failed to stop the service. Please manually stop Valkyrie after" \
                  " uninstallation is complete."
            logger.critical('Failed to stop the service. Please manually stop '
                            'Valkyrie after the uninstallation is complete.')
        removeFiles()




if __name__ == '__main__':
    main()