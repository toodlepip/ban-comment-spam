#!/usr/bin/env python
# encoding: utf-8
'''
 -- Ban Forum Spammers

 Python script to run through an Apache log file, pull out IP addresse and check
 them again stopforumspam.com website to see if they're bad. Also check to see
 if they've left a stupidly large number of comments. If so, they get banned.
 
 The aim is to block IPs that are sending commment spam at the server level so
 the minimum number of processing power is wasted in dealing with them.
 
 More info on Github: https://github.com/toodlepip/ban-comment-spam

@author:     Sam Michel
            
@copyright:  2013 Sam Michel. Some rights reserved.
            
@license:    GPL v2 License

@contact:    sam@toodlepip.co.uk
'''

import sys
import os
import time
import re
import urllib
import urllib2
import json
import subprocess
import zipfile
import sqlite3 as lite
from apachelog import apachelog
from collections import defaultdict
from pprint import pprint
from optparse import OptionParser

__all__ = []
__version__ = 0.1
__date__ = '2013-11-24'
__updated__ = '2013-11-24'

DEBUG = 1
TESTRUN = 0
PROFILE = 0
HIT_THRESHOLD = 100 # How many hits before we check an IP?
EXPIRE_AFTER = 90 # How many days before an IP is removed from list?
FORMAT = 'common' # Default format is Apache common format from Apachelog
COMMENT_LOG = 'POST /comment/reply' # Drupal comment in log uses this POST

# Pull in local configuration from local_settings.py
try:
    from local_settings import *
except:
    pass

# Global variables
con = None # Sqlite connection
cur = None # Sqlite cursor

'''
Check the format of the Apache logfile is defined grab the format from the
Apachelog module or use the custom format supplied.
'''
def check_apache_format(format='common'):
    if not format: return apachelog.formats['common']
    if format in apachelog.formats: return apachelog.formats[format]
    return format

def parse_apache_log(file=LOGFILE, threshold=HIT_THRESHOLD, \
                         exclude=''):
    dprint("\n\nProcessing apache file\n\n")
    ips = defaultdict(int) # Use defaultdict to do a simple count
    comments = defaultdict(int)
    format = check_apache_format(FORMAT)
    p = apachelog.parser(format)
        
    try:
        filehandle = open(file)
        dprint("Parsing apache log file: %s\n", file)
    except: 
        sys.stderr.write("Couldn't open log file %s\n" % file)
        sys.exit(-1)
    
    count = 0
    for line in filehandle:
        try:
            data = p.parse(line)
            ips[data['%h']] += 1
            if (re.search(COMMENT_LOG, data['%r'])):
                comments[data['%h']] += 1
            count += 1
        except:
            sys.stderr.write("Unable to parse %s\n" % line)
    dprint("Parsed %s lines from %s\n", (count, file))
    dprint("%s IP addresses posted %s comments\n", (len(comments), sum(comments.values())))
                    
    visitor_ips_to_check = []
    for ip in sorted(ips, key=ips.get, reverse=True):
        if ips[ip] < threshold:
            break
        if ip in exclude:
            continue
        visitor_ips_to_check.append(ip)
    dprint("%s IP addresses visited over %s times\n", \
                     (len(visitor_ips_to_check), threshold))
            
    # Merge list so there's no duplication in checking IP addresses
    ips_to_check = list(set(visitor_ips_to_check + comments.keys()))
    dprint("%s IP addresses to check (de-duped)\n", len(ips_to_check))
    return ips_to_check

'''
Get sqlite connection to use, creating the database and blacklist table if
they don't exist already.
'''
def get_sqlite_cursor():
    global con
    global cur
    
    if type(con) != "sqlite3.Connection":
        try:
            con = lite.connect(os.path.dirname(os.path.realpath(__file__))+'blacklist.db')  
        except lite.Error, e:
            print "Error %s:" % e.args[0]
            sys.exit(1)
            
    if type(cur) != "sqlite3.Cursor":
        cur = con.cursor()    
        cur.execute('SELECT SQLITE_VERSION()')
        data = cur.fetchone()
        dprint("Using SQLite version: %s\n", data)
        
    # Check blacklist table exists, if not, create it
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='blacklist';")
    if not cur.fetchone():
        dprint("Blacklist table not in local DB, need to create it\n")
        cur.execute("CREATE TABLE blacklist (ip TEXT PRIMARY KEY, timestamp INT)")
    else:
        cur.execute("SELECT COUNT(ip) FROM blacklist;")
        dprint("%s IPs already in database", cur.fetchone())                       

'''
Check a list of IP addresses against the local database (it's quicker). If
listed, update the timestamp in the DB
'''
def check_local(ips):
    global con
    global cur
    
    ips_to_check = []
    for ip in ips:
        cur.execute("SELECT ip FROM blacklist WHERE ip = '%s'" % ip)
        if cur.fetchone():
            dprint("%s already stored locally, updating timestamp\n", ip)
            cur.execute("REPLACE INTO blacklist (ip, timestamp) VALUES (?, ?)", \
                        (ip, int(time.time())))
            con.commit()
        else:
            ips_to_check.append(ip)
    dprint("%s IPs already in local DB\n", len(ips)-len(ips_to_check))
    
    return ips_to_check

def update_local(ips):
    global con
    global cur
    
    for ip in ips:
        cur.execute("REPLACE INTO blacklist (ip, timestamp) VALUES (?, ?)", \
            (ip, int(time.time())))
        con.commit()
        
def expire_local():
    global con
    global cur
    
    cur.execute("DELETE FROM blacklist WHERE timestamp <= %s" % int(time.time()-EXPIRE_AFTER*24*60*60))
    con.commit()
    dprint("%s IPs expired from local DB\n", cur.rowcount)
    
def get_local_ips():
    global con
    global cur
    
    cur.execute("SELECT ip FROM blacklist")
    ips = cur.fetchall()
    if ips:
        return ips
    else:
        return False
        

def main(argv=None):
    '''Command line options.'''
    
    program_name = os.path.basename(sys.argv[0])
    program_version = "v%s" % __version__
    program_build_date = "%s" % __updated__
 
    program_version_string = '%%prog %s (%s)' % (program_version, program_build_date)
    #program_usage = '''usage: spam two eggs''' # optional - will be autogenerated by optparse
    program_longdesc = '''''' # optional - give further explanation about what the program does
    program_license = ""
 
    if argv is None:
        argv = sys.argv[1:]
    try:
        # setup option parser
        parser = OptionParser(version=program_version_string, epilog=program_longdesc, description=program_license)
        parser.add_option("-i", "--in", dest="infile", help="set input path [default: %default]", metavar="FILE")
        parser.add_option("-o", "--out", dest="outfile", help="set output path [default: %default]", metavar="FILE")
        parser.add_option("-v", "--verbose", dest="verbose", action="count", help="set verbosity level [default: %default]")
        parser.add_option("-r", "--run", dest="run", action="store_true", help="process the apache log and ban spammers")
        parser.add_option("-s", "--stats", dest="stats", action="store_true", help="show basic stats about IPs stored")
        
        # set defaults
        parser.set_defaults(outfile="./out.txt", infile="./in.txt")
        
        # process options
        (opts, args) = parser.parse_args(argv)
        
        if opts.verbose > 0:
            print("verbosity level = %d" % opts.verbose)
        #if opts.infile:
            #print("infile = %s" % opts.infile)
        #if opts.outfile:
            #print("outfile = %s" % opts.outfile)
            
        # MAIN BODY #

        if opts.run:
        
            dprint("Starting ban-them run %s\n", time.ctime())
                
        #1. Parse the apache log to see if get IPs which have posted comments
        #   and those which have looked at loads of pages
            
            ips_to_check = parse_apache_log(file=LOGFILE, \
                threshold=HIT_THRESHOLD, \
                exclude=EXCLUDE_IPS if 'EXCLUDE_IPS' in globals() else '')
        
        #2. Check the IPs against the local database to see if they're already
        #   listed as baddies. If they're in there update timestamp
        
            get_sqlite_cursor() # Setup local DB, creating if necessary
            ips_to_check = check_local(ips_to_check)
      
        #2. Run those bad IPs past http://stopforumspam.com who maintain a 
        #   good list of Forum spammers. No API key is required, but there is
        #   a cap on how many calls can be made. Suggest running this script
        #   once/day. More info: http://www.stopforumspam.com/usage

            ips_to_check = check_sfs(ips_to_check)
            
        #3. Update the baddie IPs into local DB, expire any that are out of
        #   date and grab the final blacklist to be added to firewall    
        
            update_local(ips_to_check)
            expire_local()
            blacklist = get_local_ips()
            if not blacklist:
                dprint("No IPs to add to iptables, possibly something wrong\n")
                sys.exit()

        #4. Time to update the firewall, setting the rules and ipset if they
        #   don't exist already.

            dprint("Updating ipset and iptables with %s new IPs\n", len(blacklist))
            
            # Create blacklist set, will fail gracefully if it exists already
            dprint("Create blacklist set\n")
            try:
                subprocess.check_call(["ipset", "--create", "blacklist", "iphash", "--hashsize", "4096"])
            except:
                pass
            
            dprint("Check blacklist set is listed in iptables\n")
            p = subprocess.Popen(["iptables", "-L", "-n"], stdout=subprocess.PIPE).communicate()[0]
            match = re.search('match-set blacklist src', p)
            if not match:
                dprint("Adding blacklist set to top of iptables\n")
                subprocess.check_call(["iptables", "-I", "INPUT", "1", "-m", "set", "--set", "blacklist", "src", "-j", "DROP"])
            
            # Flush blacklist of existing values
            dprint("Flush blacklist set before re-filling with IPs\n")
            subprocess.check_call(["ipset", "--flush", "blacklist"])
            
            dprint("Adding new IPs to blacklist set\n")
            for ip in blacklist:
                subprocess.check_call(["ipset", "--add", "blacklist", "%s" % ip])
            
            dprint("Finishing ban-them run %s\n\n\n", time.ctime())
            
            sys.exit()
            
        if opts.stats:
            get_sqlite_cursor()
            cur.execute("SELECT COUNT(*) FROM blacklist")
            sys.stdout.write("%s IPs stored in DB\n" % cur.fetchone())
      
        
    except Exception, e:
        indent = len(program_name) * " "
        sys.stderr.write(program_name + ": " + repr(e) + "\n")
        sys.stderr.write(indent + "  for help use --help")
        return 2
    
def dprint(text="", data=[]):
    if DEBUG:
        sys.stdout.write(text % data)
    
def check_sfs(ips):
    _to_blacklist = []
    for i in xrange(0, len(ips), 15):
        ip_to_check = [ip for ip in ips[i:i+15]]
        q = "ip[]=" + "&ip[]=".join(ip_to_check) + "&f=json"
        #req = urllib2.Request('http://www.stopforumspam.com/api', data)
        req = urllib2.Request('http://www.stopforumspam.com/api?%s' % q)
        try:
            response = urllib2.urlopen(req)
            data = json.loads(response.read())
            for rec in data['ip']:
                if rec['appears'] == 1:
                    _to_blacklist.append(rec['value'])
                    dprint("%s is *blacklisted*\n", rec['value'])
                else:
                   dprint("%s is NOT blacklisted\n", rec['value'])
        except urllib2.URLError, e:
            print e
            sys.exit()
    return _to_blacklist

if __name__ == "__main__":
    main()
    if DEBUG:
        sys.argv.append("-h")
    if TESTRUN:
        import doctest
        doctest.testmod()
    if PROFILE:
        import cProfile
        import pstats
        profile_filename = '_profile.txt'
        cProfile.run('main()', profile_filename)
        statsfile = open("profile_stats.txt", "wb")
        p = pstats.Stats(profile_filename, stream=statsfile)
        stats = p.strip_dirs().sort_stats('cumulative')
        stats.print_stats()
        statsfile.close()
        sys.exit(0)
    sys.exit()