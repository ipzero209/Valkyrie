# Valkyrie
Allows you to perform limited filtered forwarding of logs from Palo Alto Networks' Logging Service

## This is an Alpha release. No testing has been completed yet - Do not use in production

## A more detailed readme to follow.



## Dependencies

1. Linux: This project was written for use on Ubuntu, but will work on any
modern Linux distribution. It does use initd for service management, but you
can adapt it to use systemd as needed.
2. Python Modules:

   A. requests: This is a widely used module for HTTP requests. Information can be
  found here:
  
       i. [Github repo](https://github.com/requests/requests)  
       ii. [Docs](http://docs.python-requests.org/en/master/)  
   B. xml.etree.ElementTree: This module is included with most installations of Python
   
   C. os: This module is included with most python installations.
   
   D. logging: This module is included with most python installations.
   
   E. shelve: This module is included with most python installations.
   
   F. multiprocessing: This module is included with most python installaitons.
3. TLS Version

    As of PAN-OS 8.0 the management interface on Panorama no longer supports connecting using
    TLS1.0 by default. In order for this script to work, you will need to either:
    1. Apply an SSL/TLS service profile which explicitly allows TLS1.0 to the management interface
    on Panorama, OR
    2. Upgrade the version of OpenSSL on the host where the script will be running to version 1.0.2
    (minimum).
    
## Requirements:

1. Python 2.7
2. Connectivity between the host running the script and the management interface of
Panorama.
3. This script uses the XML API to send queries to Panroama. It is recommended that a
unique API admin account be created specifically for the script. There are two options
for creating this API user account:

     A. Create the accoung as a 'superreader'
     
     B. Create a custom admin role. If you choose to use a custom admin role, the
     settings need to include:
     
        i. Type: Panorama
        ii. Access: Log & Operational Commands

## Installation

1. Download the release.
2. Transfer to the host that will be running the script.
3. Unpack the archive.
4. Run the setup using 'sudo ./v_setup.py --install' (the short option -i may 
also be used).
5. Follow the on screen prompts.
6. Verify that the service is running:

    A. 'sudo service valkyrie status'
    B. 'ps -ef | grep python' - you should see multiple processes for valkyrie.
    
## Configuration

The conf file is located at '/etc/valkyrie/valkyrie.conf'. There are currenly 
currently two supported configuration lines:

1. LEVEL: This is a tuple that dictates the logging level of the script. Values
can be one of:

    A. DEBUG
    
    B. INFO
    
    C. WARNING
    
    D. ERROR
    
    E. CRITICAL

2. Forwarding process. This takes the form of 'LOGTYPE:QUERY:DESTINATION'

    A. LOGTYPE: Can be one of TRAFFIC, THREAT, URL, WILDFIRE.
    
    B. QUERY: Query string to match. Uses the same query syntax as Panorama 
    (e.g. 'subtype eq spyware').
    
    C. DESINATION: IP address or FQDN of the syslog destination that you want to
    send logs to. 

To chang your query processes, make the appropriate change to the conf file then
restart the service ('sudo service valkyrie restart').


## Ongoing Operations

While Valkyrie is meant to be a fire and forget script, you may need to change
the password for the API user. To update the API key, simply run v_setup.py with
the --renew option (the short option -r can be used as well).


## Uninstalling

To uninstall Valkyrie, simply run the setup script with the --uninstall option
(the short option -u can be used as well).
 

