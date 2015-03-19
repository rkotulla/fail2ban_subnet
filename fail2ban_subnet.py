#!/usr/bin/env python


#
# General settings go here
#
whois_fullpath = "/usr/bin/whois"
iptables_fullpath = "/usr/sbin/iptables"

email_from = "fail2ban@galev.org"
email_to = "ralf.kotulla@gmail.com"
email_subject = "Fail2Ban blocking Subnet"

block_log = "/etc/fail2ban/block_subnet.log"
mincount = 3

ipchain_rule = "fail2ban_subnet"


#
# code goes below here
#

import os, sys, numpy, subprocess
import datetime

rules = ['ssh-iptables', 'ssh-repeater']

import re
p = re.compile('\[ssh-iptables\] Ban')

# Import smtplib for the actual sending function
import smtplib

# Import the email modules we'll need
from email.mime.text import MIMEText

import time



class Fail2Ban_SubnetBlocker( ):

#   blocked_subnets = []

    def __init__(self, logfile):

        self.blocked_subnets = []
        self.logfile = logfile
        self.setup_ipchain_dictionary()


    def startup(self):
        self.setup_iptables_rule()
        self.block_known_subnets()

    def verify_root_access(self):
        ret = self.run_iptables("--new-chain fail2ban_root_check")
        self.run_iptables("--delete-chain fail2ban_root_check")
        return (ret == 0)

    def setup_ipchain_dictionary(self):
        self.iptables_dict = {
            "IPCHAIN": ipchain_rule,
            }

    def run_iptables(self, cmd):

        _cmd = cmd
        for key in self.iptables_dict:
            _cmd = _cmd.replace("<%s>"%key, self.iptables_dict[key])

        full_cmd = "%s %s" % (iptables_fullpath, _cmd)
        ret =  os.system(full_cmd)
        print full_cmd, ret
        return ret
        
    def setup_iptables_rule(self):

        
        # Add the table to check for blocked subnets
        ret = self.run_iptables("-n --list <IPCHAIN>")
        if (not ret == 0):
            # self.run_iptables("--delete INPUT <IPCHAIN>")
            self.run_iptables("--new-chain <IPCHAIN>")

            # Add an entry to use the new table
            self.run_iptables("--insert INPUT -j <IPCHAIN>")
        
        pass

    def block_known_subnets(self):

        with open(block_log, "r") as log:
            for line in log.readlines():
                items = line.split()
                subnet = items[0]
                print "Blocking known subnet:", subnet
                self.add_blocking_iptables_entry(subnet)


    def delete_add_iptables_rule(self, rule):
        #print "\n\nNEW RULE\n"+rule+"\n\n"
        if (self.run_iptables("--check "+rule)):
            #self.run_iptables("--delete "+rule)
            self.run_iptables("--append "+rule)
        return

    def add_blocking_iptables_entry(self, subnet):
        
        level = len(subnet.split("."))
        full_ip = "%s.%s" % (subnet, ".".join(['0']*(4-level)))

        source = "%(ip)s/%(subnet_bits)d" % {
            "ip": full_ip,
            "subnet_bits": level*8,
            }

        # Try to delete the rule first
        rule = "<IPCHAIN> -p tcp -s %s -j REJECT --reject-with tcp-reset" % (source)
        self.delete_add_iptables_rule(rule)

        rule = "<IPCHAIN> -p all -s %s -j DROP" % (source)
        self.delete_add_iptables_rule(rule)

        self.blocked_subnets.append(subnet)

        return


    def read_logfile(self):
        try:
            self.f2blog = open(self.logfile, "r")
        except:
            print "Unable to open logfile"
            return None

        self.banned_hostnames = []
        for line in self.f2blog.readlines():
            line = line.strip()
            #print line.strip()

            if (re.search(p, line) != None):
                #print "found match:",line

                hostname = line.split()[-1]
                #print "-->",hostname

                self.banned_hostnames.append(hostname)

        #print set(self.banned_hostnames)



    def find_subnets_to_block(self, level, mincount):
        
        #
        # Now search for common subnets
        #
        unique_ips = list(set(self.banned_hostnames))

        subnets = [".".join(ip.split(".")[:level]) for ip in unique_ips]

        unique_subnets = set(subnets)

        #print unique_ips[:5]
        #print subnets[:5]

        #print unique_subnets

        #
        # Now count how many times each subnet was found
        #
        block_subnets = []
        for idx, sn in enumerate(unique_subnets):
            subnet_count = subnets.count(sn)
            # print sn, "-->", subnet_count
            if (subnet_count >= mincount):
                if (sn in self.blocked_subnets):
                    # print "This subnet (%s) is already blocked" % (sn)
                    pass
                else:
                    print "found new suspicious subnet:",sn,subnet_count
                    block_subnets.append((sn, subnet_count))

        # print block_subnets

        return block_subnets

    # for sn in block_subnets:
    #     os.system("whois %s.255" % (sn))

    def send_whois_email(self, subnet, count):

        level = len(subnet.split("."))
        #print level, ".".join(['255']*(4-level))
        full_ip = "%s.%s" % (subnet, ".".join(['255']*(4-level)))
        print full_ip


        whois_cmd = "%s %s" % (whois_fullpath, full_ip)
        try:
            ret = subprocess.Popen(whois_cmd.split(), 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE)
            (whois_stdout, whois_stderr) = ret.communicate()
            if (ret.returncode != 0):
                pass
                # logger.debug("Stderr=\n"+sex_stderr)
        except OSError as e:
            print >>sys.stderr, "Execution failed:", e


        #
        #
        #
        from_ip = "%s.%s" % (subnet, ".".join(['0']*(4-level)))
        to_ip = "%s.%s" % (subnet, ".".join(['255']*(4-level)))
        ip_blockcount = count

        #
        # Add some info to the email
        #
# From: %(from)s
# To: %(to)s
# Subject: %(subject)s
        email = """\
The following IP address subnet has been blocked after too many failed 
login attempts:

%(from_ip)s -- %(to_ip)s

Blocked IPs in that range: %(ip_blockcount)d

--------------------------------------
--------------------------------------

Whois information:

%(whois)s

""" % {
            "from": email_from,
            "to": email_to,
            "subject": email_subject,
            "from_ip": from_ip,
            "to_ip": to_ip,
            "ip_blockcount": ip_blockcount,
            "whois": whois_stdout,
            }
        # print email

        msg = MIMEText(email)
        # me == the sender's email address
        # you == the recipient's email address
        # email_subject = 
        msg['Subject'] = "[Fail2Ban] Blocking subnet %s/%d (%d)" % (subnet, level*8, ip_blockcount)
        msg['From'] = email_from
        msg['To'] = email_to

        # Send the message via our own SMTP server, but don't include the
        # envelope header.
        s = smtplib.SMTP('localhost')
        s.sendmail(email_from, [email_to], msg.as_string())
        s.quit()
        # print msg

        

    def _add_subnet_to_log(self, subnet):

        with open(block_log, "a") as log:
            print >>log, subnet, str(datetime.datetime.now())

    def block_all_suspicious_subnets(self, block_subnets):

        for (subnet, count) in block_subnets:

            # Add this IP range to list of blocked subnets
            self.add_blocking_iptables_entry(subnet)

            self._add_subnet_to_log(subnet)

            self.send_whois_email(subnet, count)



if __name__ == "__main__":
    logfile = sys.argv[1]

    f2b = Fail2Ban_SubnetBlocker(logfile)

    root = f2b.verify_root_access()
    if (not root):
        print """\
*****************************************************************
*                                                               *
*        This program required root access to work!!!           *
*                                                               *
*****************************************************************"""
        sys.exit(1)

    f2b.startup()
    try:
        while (True):
            print datetime.datetime.now()
            f2b.read_logfile()
            subnets = f2b.find_subnets_to_block(level=3, mincount=mincount)
            f2b.block_all_suspicious_subnets(subnets)
            time.sleep(30)
    except (SystemExit, KeyboardInterrupt):
        print "\rShutting down"
    except Exception as e:
        print e
        pass



