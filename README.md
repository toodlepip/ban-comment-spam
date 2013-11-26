# ban-comment-spam

Script for testing IPs in Apache Logs against StopForumSpam.com and banning
them, if they're evil.

## Introduction

One of our sites suffers from huge amounts of comment spam. Virtually all of it
is trapped by CAPTCHAs on the Drupal system that runs the site. However, the
comment spammers are so prolific it hammers the CPU of the site.

In effect it's a DDoS attack through comments. The aim of this script is to
stop or at least limit the effects of this by blocking offending IPs at the
firewall level.

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



 