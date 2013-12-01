# ban-comment-spam

Script for testing IPs in Apache Logs against StopForumSpam.com and banning
them, if they're evil.

**USE THIS SCRIPT AT YOUR OWN RISK - IF USED IN FULL IT'LL CHANGE THE FIREWALL
ON YOUR SERVER. BACKUPS AND TESTING ARE YOUR FRIENDS**

## Introduction

One of our sites suffers from huge amounts of comment spam. Virtually all of it
is trapped by CAPTCHAs on the Drupal system that runs the site. However, the
comment spammers are so prolific it hammers the CPU of the site.

In effect it's a DDoS attack through comments. The aim of this script is to
stop or at least limit the effects of this by blocking offending IPs at the
firewall level.

This script is based on Drupal but could be tailored to other CMSes that have
a set pattern for posting comments. Alter the COMMENT_LOG global to change
the pattern searched.

## Installation and use

Requirements:

+ Python v2.6+
+ Python sqlite module (should be in Python by default)
+ ipset
+ Local access to apache log file

It should be dead easy to use this script:

<code>python ban-them.py --run</code>

which will run the script on the local version of the apache log file. It'll
process the file, pull out any IPs that meet HIT_THRESHOLD (default: 100) and
any IPs that have left comments.

These IPs are checked to see if they're on the list and timestamp updated. If
they're not listed, they are tested against the StopForumSpam.com API to see if
they're baddies. If so, they're added an ipset called <code>blacklist</code> 
which is created if it doesn't exist.

Finally, the DB is checked for any IPs that haven't spammed for EXPIRE_AFTER
(default is 90) days. Hopefully ISPs are dropping baddies from their users and
so we give a fair crack of the whip to new users of those IPs. 

## Methodology

+ Analyse the site's Apache log files (probably daily)
+ Pull any IPs that have visited very frequently or submitted a comment
+ Test against http://www.stopforumspam.com (SFS) API
+ Log IP in database with timestamp
+ Add IP to firewall and drop any inbound traffic
+ Periodically review DB and remove IP if no longer listed on SFS 

## Installing ipset

It's possible to use [iptables](http://ipset.netfilter.org/iptables.man.html)
to manage the blocking on small lists of IP addresses. The first run revealed
at least 500 IPs that needed to be blocked.

Fortunately, [ipset](http://ipset.netfilter.org/) provides a very efficient
way of managing huge sets of IP addresses.

On most Linux systems it's pre-compiled and easy to install, on Debian Squeeze
it's a bit more fiddly. Fortunately, there's some useful instructions to
[install ipset on Debian Squeeze on the Olden Gremlin blog](http://oldengremlin.blogspot.co.uk/2010/12/debian-squeeze-ipset-tarpit-2632.html):

1. aptitude install module-assistant xtables-addons-source
1. module-assistant prepare
1. module-assistant auto-install xtables-addons-source
1. depmod -a

N.B. Must be installed and run as root.

## References

+ [Mass-blocking IP addresses with ipset](http://daemonkeeper.net/781/)
+ [ipset tibs & examples](http://ipset.netfilter.org/tips.html)
+ [Drop IP addresses using iptables](http://www.cyberciti.biz/faq/linux-iptables-drop/)
+ [Using iptables & ipset](http://raid6.com.au/~onlyjob/posts/iptables-ipset/)

## Thanks

Thanks to all the reference info listed above and to
[Chinwag](http://chinwag.com) for giving me the time to develop this. 