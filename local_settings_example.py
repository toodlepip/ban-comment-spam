'''

local_settings.py

Use this file for system-specific settings. See below for more info.

MAKE CHANGES AND SAVE THIS FILE AS local_settings.py

'''

'''
HIT_THRESHOLD is the number of hits in the Apache log that an IP address makes
before we get suspicious and check it out against StopForumSpam.com website.

The default is 100 hits which should exclude most of the casual users who are
visiting just a few pages on a low traffic site. For larger sites especially
those with lots of images this may need to be higher. No harm done except it'll
mean checking a lot of IP addresses.  
'''

HIT_THRESHOLD = 100

'''
LOGFILE is the path to the Apache log file. It needs to be unzipped to be
processed. If it's not local, you'll need to have a cron job to sftp or scp
it to a local directory. By convention we're using .log suffix for log files.
'''

LOGFILE = '/path/to/apache.log'

'''
FORMAT is used to define the type of Apache log format, this is taken from
the Apachelog Python module. Or a custom format can be used if a special
format is used in your Apache logs. Default is common. Options are:

# Common Log Format (CLF)
FORMAT = 'common' which uses r'%h %l %u %t \"%r\" %>s %b'

# Common Log Format with Virtual Host
FORMAT = 'vhcommon' which uses r'%v %h %l %u %t \"%r\" %>s %b'

# NCSA extended/combined log format
FORMAT = 'extended' which uses r'%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"'

or a custom string could be used e.g.
FORMAT = r'%h %v %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" \"%{Cookie}i\"'

'''
FORMAT = 'common'

'''
EXCLUDE_IPS is a list of IP addresses that shouldn't be checked against the
StopForumSpam API. Typically they'll be home/office/development IPs. Replace
these IPs with real ones.
'''

EXCLUDE_IPS = [
               '127.0.0.1', # Office IP
               '10.10.10.1' # Home IP
               ]

'''
IPSET & IPTABLES - if the executables aren't on the path or installed in a 
non-standard place, put the full path to the executable below. Defaults are
used.
'''

IPSET = 'ipset'
IPTABLES = 'iptables'

'''
COMMENT_LOG can be used to customise the pattern that's used to search for
comment submissions in the Apache logs.
'''
COMMENT_LOG = 'POST /comment/reply'