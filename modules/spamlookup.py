import socket
from loguru import logger

def spam_lookup(ipaddr):
	bl = ['ubl.unsubscore.com','dyna.spamrats.com','dnsbl-3.uceprotect.net','dnsbl-1.uceprotect.net','rf.senderbase.org','spam.dnsbl.sorbs.net','bl.spameatingmonkey.net','bl.spamcannibal.org','socks.dnsbl.sorbs.net','spam.spamrats.com','smtp.dnsbl.sorbs.net','ips.backscatterer.org','bl.blocklist.de','zen.spamhaus.org','rbl.interserver.net','rbl.abuse.ro','dnsbl-2.uceprotect.net','cncdl.anti-spam.org','dnsbl.dronebl.org','query.senderbase.org','sa.senderbase.org','cbl.anti-spam.org','b.barracudacentral.org','spam.dnsbl.anonmails.de','web.dnsbl.sorbs.net','pbl.spamhaus.org','bl.spamcop.net','http.dnsbl.sorbs.net','dnsbl-0.uceprotect.net','dnsbl.sorbs.net','csi.cloudmark.com','zombie.dnsbl.sorbs.net','noptr.spamrats.com','xbl.spamhaus.org','bl.score.senderscore.com','bl.mailspike.net','sbl.spamhaus.org','misc.dnsbl.sorbs.net','dul.dnsbl.sorbs.net','cbl.abuseat.org','multi.surbl.org']
	ip_rev = '.'.join(str(ipaddr).split('.')[::-1])
	listed = 0
	l_rbl  = []
	for i in bl:
		try:
			#Lookup  happens here - if gethostbyname fails the ip is not listed
			# logger.debug(f'[l] i: {i} {ip_rev}')
			socket.gethostbyname(ip_rev + '.' + i + '.')  # final dot to avoid localhost lookups in some env
			l_rbl += [i]
			listed+= 1
		except socket.gaierror as e:
			logger.error(f'[!] Error: {e} {type(e)} for address {ipaddr}')
			return None
		except Exception as e:
			logger.error(f'[!] Error: {e} {type(e)} for address {ipaddr}')
			return None
	return [str(listed), l_rbl]	
