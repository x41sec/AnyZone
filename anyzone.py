#!/usr/bin/env python3

import sys, time, random, socket, ipaddress
import dnslib  # apt install python3-dnslib, or the 'dnslib' folder within https://github.com/paulc/dnslib (ea9b2df at the time of writing)
import ratelimit

HOUR = 3600  # convenience value for readability below

STATS_EVERY = 1337  # every how many incoming packets should, on average, stats be printed. Set to False to disable.
RL_RATE = 9000  # For RL_* settings documentation, see ratelimit.py -> FARL -> __init__ docstring
RL_PER = 18000  # Basically: every client can do RATE queries per PER seconds (excess queries are ignored). They can also burst all the way up to RATE instantly.
               # You'll want to set these much lower than your server can support because every kilobyte is another kilobyte towards (moderate) amplification.
               # Note that only outgoing packets matter. They won't be limited for sending garbage
RL_MAX_ENTRIES = 9000
RL_CLEANUP_EVERY = 10
MAX_TRAFFIC_RATE = RL_RATE * 25   # MAX_TRAFFIC_* settings are not per-client but global. Works the same as the RL_* settings. Use this to limit outgoing packet rates.
MAX_TRAFFIC_PER = RL_PER * 2      # Packet size depends on e.g. your zone name, but estimate with ~130 bytes (eth+ip+udp headers included).
                                  #   monthly bandwidth (GB) = MAX_TRAFFIC_RATE / MAX_TRAFFIC_PER * 3600*24*30 * 130 / 1e9
                                  #   max burst size (bytes) = MAX_TRAFFIC_RATE * 130
                                  #   average bytes/second   = MAX_TRAFFIC_RATE / MAX_TRAFFIC_PER * 130
RATE_LIMIT_INFORM_RATE = 5  # 1 in N chance to inform a client when a rate limit was exceeded using a tiny UDP response (non-DNS). For strict outgoing bandwidth limit, set to False
BINDPROTO = socket.AF_INET6
BINDIP = '::'  # on Linux, '::' with BINDPROTO=socket.AF_INET6 binds to both v4 and v6 unless you changed something in /proc/sys/net iirc
BINDPORT = 53
MAXPACKETSIZE = 1400  # incoming packets only. Outgoing are always as small as possible
TTL_DEFAULT = 24*HOUR  # TTL for answering queries like the A record of $zonename, which might change if you move to another server
TTL_NS = 2147483647  # max as per https://webmasters.stackexchange.com/a/115401/28564 because the answer for A/NS 192.168.1.1.$zonename will always be the same: 192.168.1.1
LEGALCOLON = 'i'  # because 2a01::1.ns.example.org is not a valid name, we need some replacement for the :. What do you want it to be?
SOA_EMAIL = 'x41-dsec.de'  # should be the operator's email address, formatted as DNS name... just check our website I say
SOA_SERIAL = 1337  # only useful for zone transfers. Since we won't be doing zone transfers here, this can be a dummy value from my understanding
SOA_REFRESH = TTL_DEFAULT  # time to re-query SOA record for zone changes. I guess the operator email might change, else you might as well set int_max
SOA_RETRY = SOA_REFRESH - 1  # "must be less than Refresh" but also only useful for secondary servers which we don't have here
SOA_EXPIRE = SOA_REFRESH + SOA_RETRY + 1  # "must be bigger than the sum of Refresh and Retry" but also only useful for secondary servers...
SOA_TTL = TTL_DEFAULT  # number of seconds to cache negative responses for. We might add features like AAAA, CAA records on $zonename so this should be a reasonable time
                       # typically called MINIMUM, its current meaning is a TTL for negative responses
VERSION_STRING = 'AnyZone DNS (http://anyz.one)'  # if you wish to identify the server software, set to False to disable
SUPPORT_WWW = True  # respond to queries for "www." + $zonename with an A record containing $serverip
SUPPORT_OWNIP = True  # respond to queries for $serverip.$zonename with an A record containing $serverip
SUPPORT_WHATISMYIP = True  # respond with the remote address when asked for ip.$zonename or myip.$zonename or whatismyip.$zonename


def tryParseIP(string):
    try:
        return ipaddress.ip_address(string)
    except ValueError:
        return False


if '--help' in sys.argv or '-h' in sys.argv or len(sys.argv) != 3:
    print(f'''
AnyZone - DNS zones for everyone, custom made for any IP!

Usage:
  {sys.argv[0]} <zonename> <serverip>

Where
  <zonename> is the name of our zone that was delegated to this server,
      e.g. ns.example.org.
  <serverip> is the IP of this system, to answer A <zonename> queries,
      e.g. 45.80.169.218 (todo: add ipv6 support for this)

In your domain's DNS settings, you need to delegate this <zonename> to a name
which then has an A record for <serverip>. Once you have done that, you will
be able to query:

  $ dig anything.192.168.1.1.<zonename>  # ask 192.168.1.1
  $ dig anything.2001idb8ii1.<zonename>  # ask 2001:db8::1

The queries will show up on the respective IPs, relative to the resolver (by
default, probably your ISP). The point is that you can fill in any IP, both v4
and v6, and you will get the traffic for it on your server. The intended
purposes are penetration tests and DNS tunneling.

The project is pure Python and meant to handle Internet exposure, but it has
not been audited for security. Deployment on an isolated, unimportant system,
IP address, and domain is the recommended setup.

Every line of output starts with a message level, loosely corresponding to the
flowchart in version 1 of: https://stackoverflow.com/a/64806781/1201863
Global issues: Warn/Error/Fatal (stderr)
One client having trouble: Info (stdout)
Normal operation: Debug (stdout)
On startup, if Python throws a backtrace (e.g. fails to bind to port), Python
will not use this convention as well as exit.
'''.lstrip())
    sys.exit(1)

zonename = sys.argv[1].lower()  # lower() once so that we don't have to do it for every comparison later
serverip = sys.argv[2]

# keeping it DRY, but root records are not simply static because the qname carries case randomization
# it might be more efficient to define a static value and updating the qname property before returning it, but something something premature optimization
versiondbind = lambda qname: dnslib.RR(qname, dnslib.QTYPE.TXT, ttl=TTL_DEFAULT, rdata=dnslib.TXT(VERSION_STRING), rclass=dnslib.CLASS.CH)
root_RR_SOA  = lambda qname: dnslib.RR(qname, dnslib.QTYPE.SOA, ttl=TTL_DEFAULT, rdata=dnslib.SOA(zonename, SOA_EMAIL, (SOA_SERIAL, SOA_REFRESH, SOA_RETRY, SOA_EXPIRE, SOA_TTL)))
root_RR_NS   = lambda qname: dnslib.RR(qname, dnslib.QTYPE.NS,  ttl=TTL_DEFAULT, rdata=dnslib.NS(zonename))
RR_A    = lambda qname, val: dnslib.RR(qname, dnslib.QTYPE.A,   ttl=TTL_DEFAULT, rdata=dnslib.A(val))
RR_AAAA = lambda qname, val: dnslib.RR(qname, dnslib.QTYPE.AAAA,ttl=TTL_DEFAULT, rdata=dnslib.AAAA(val))

rl_per_client = ratelimit.FARL(rate=RL_RATE, per=RL_PER, maxEntries=RL_MAX_ENTRIES, cleanupEvery=RL_CLEANUP_EVERY)
rl_global = ratelimit.FARL(rate=MAX_TRAFFIC_RATE, per=MAX_TRAFFIC_PER, maxEntries=1, cleanupEvery=False)

sock = socket.socket(BINDPROTO, socket.SOCK_DGRAM)
# use REUSEADDR if you want to allow multiple processes to be bound to the same port (via <https://stackoverflow.com/a/577905/1201863>)
#sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((BINDIP, BINDPORT))

starttime = time.time()
packets_incoming = 0
packets_outgoing = 0

if zonename[0] == '.':
    sys.stderr.write('Fatal: zone name starts with a dot. This would result in impossible values\n')
    sys.exit(2)

if zonename[-1] != '.':
    zonename += '.'
    sys.stderr.write('Warn: added . after your zonename because the root is missing and dns queries would not match\n')

sys.stdout.write('Debug: bound and ready to receive my first packet. Exciting!\n')

while True:
    try:
        msg, addr = sock.recvfrom(MAXPACKETSIZE)
        packets_incoming += 1
    except KeyboardInterrupt:
        sys.exit(0)

    if STATS_EVERY != False and random.randrange(STATS_EVERY) == 1:
        t = time.time()
        ipps = round(packets_incoming / (t - starttime))
        opps = round(packets_outgoing / (t - starttime))
        sys.stdout.write(f'Debug: packets incoming {packets_incoming} ({ipps}/s), outgoing {packets_outgoing} ({opps}/s)\n')

    try:
        try:
            q = dnslib.DNSRecord.parse(msg)
        except Exception as e:
            # TODO should we return a FORMERR instead?
            sys.stdout.write(f'Info: failed to parse as DNS, ignoring packet from {addr}\n')
            continue

        if len(q.questions) != 1:
            # TODO should we return a FORMERR instead?
            sys.stdout.write(f'Info: number of queries != 1, ignoring packet from {addr}\n')
            continue

        # we will send a response packet below. Let's check rate limits

        if not rl_global.status("it's me, mario!").ok:
            if RATE_LIMIT_INFORM_RATE != False and random.randrange(RATE_LIMIT_INFORM_RATE) == 1:
                sys.stderr.write(f'Warn: global rate limit exceeded, informing {addr}\n')
                sock.sendto(b'global rate limit exceeded', addr)
            else:
                sys.stderr.write(f'Warn: global rate limit exceeded, ignoring packet from {addr}\n')
            continue

        if addr[0].startswith('::ffff:') and '.' in addr[0]:
            fromip = ipaddress.ip_address(addr[0][7 : ])
        else:
            fromip = ipaddress.ip_address(addr[0])

        status = rl_per_client.status(str(fromip))
        if not status.ok:
            if status.reason == ratelimit.REASON_TABLEFULL:
                if RATE_LIMIT_INFORM_RATE != False and random.randrange(RATE_LIMIT_INFORM_RATE) == 1:
                    sys.stderr.write(f'Error: per-client rate limit table full, cannot add client, informed {addr}\n')
                    sock.sendto(b'global client limit exceeded', addr)
                else:
                    sys.stderr.write(f'Error: per-client rate limit table full, cannot add client {addr}\n')
                continue

            if RATE_LIMIT_INFORM_RATE != False and random.randrange(RATE_LIMIT_INFORM_RATE) == 1:
                sys.stdout.write(f'Info: client exceeded rate limit, informing {addr}\n')
                sock.sendto(b'per-IP rate limit exceeded', addr)
            else:
                sys.stdout.write(f'Info: client exceeded rate limit, ignoring packet from {addr}\n')
            continue

        r = q.reply(aa=True, ra=False)  # aa = authoritative answer, ra = recursion available
        r.header.ad = False  # authenticated data. RFC3655: "An authoritative server MUST only set the AD bit for authoritative answers from
                             # a secure zone if it has been explicitly configured to do so.  The default for this behavior SHOULD be off."

        qname = str(q.questions[0].qname)
        qnamelower = qname.lower()
        qtype = q.questions[0].qtype

        # all looks good, we're going to reply with 1 packet anyway so let's increment here
        packets_outgoing += 1

        if qnamelower == 'version.bind.' and VERSION_STRING:
            sys.stdout.write(f'Debug: "{qname}" and VERSION_STRING != False, returning "{VERSION_STRING}" to {addr}\n')
            r.add_answer(versiondbind(qname))
            sock.sendto(r.pack(), addr)
            continue

        if not qnamelower.endswith(zonename):
            sys.stdout.write(f'Info: "{qname.lower()}" is outside our zone, refusing query from {addr}\n')
            r.header.rcode = dnslib.RCODE.REFUSED
            r.header.aa = False
            sock.sendto(r.pack(), addr)
            continue

        if SUPPORT_WHATISMYIP and qnamelower in ['whatismyip.' + zonename, 'myip.' + zonename, 'ip.' + zonename]:
            remote_addr = ipaddress.IPv6Address(addr[0])
            remotev6 = (remote_addr.ipv4_mapped is None)
            if qtype in (dnslib.QTYPE.A, dnslib.QTYPE.ANY):
                if not remotev6:  # if they're asking for A using v6 then we return without adding an answer here
                    r.add_answer(RR_A(qname, str(remote_addr.ipv4_mapped)))
            if qtype in (dnslib.QTYPE.AAAA, dnslib.QTYPE.ANY):
                if remotev6:  # if they're asking for AAAA using v4 then we return without adding an answer here
                    r.add_answer(RR_AAAA(qname, remote_addr.compressed))
            sys.stdout.write(f'Debug: answering "{qname}" for {addr}\n')
            sock.sendto(r.pack(), addr)
            continue

        if qnamelower == zonename or (SUPPORT_WWW and qnamelower == 'www.' + zonename) or (SUPPORT_OWNIP and qnamelower == serverip + '.' + zonename):
            # technically 'www.' and '$serverip.' are not the same and shouldn't have a SOA record but... keep it simple, since it shouldn't matter
            if qtype in (dnslib.QTYPE.A, dnslib.QTYPE.ANY):
                sys.stdout.write(f'Debug: qtype A for "{qname}", returning {serverip} to {addr}\n')
                r.add_answer(RR_A(qname, serverip))
                # ANY should also include our NS and SOA but they already found us anyway so... let's limit amplification gains. Not sure we should respond to ANY anyway
            elif qtype == dnslib.QTYPE.NS:
                sys.stdout.write(f'Debug: qtype NS for "{qname}", returning {zonename} answer with {serverip} glue to {addr}\n')
                r.add_answer(root_RR_NS(qname))
                r.add_ar(RR_A(qname, serverip))
            elif qtype == dnslib.QTYPE.SOA:
                sys.stdout.write(f'Debug: qtype SOA for "{qname}", returning answer to {addr}\n')
                # If we're returning SOAs for NODATAs anyway, then it's just as amplifiable to also add one in the form of an answer
                r.add_answer(root_RR_SOA(qname))
            else:
                try:
                    qtypename = dnslib.QTYPE[qtype]
                except dnslib.DNSError:
                    qtypename = str(qtype) + '(?)'
                sys.stdout.write(f'Debug: qtype {qtypename} for "{qname}", returning NODATA to {addr}\n')
                # Adding a SOA record turns this into a NODATA response and lets clients cache this response. IIUC.
                r.add_auth(root_RR_SOA(qname))
            sock.sendto(r.pack(), addr)
            continue

        prefix = qname.lower()[ : -len(zonename) - 1].replace(LEGALCOLON, ':').replace('-', '.')
        parsedIP = False

        if '.' not in prefix:  # single label, let's see if this is an IP
            parsedIP = tryParseIP(prefix)
        if parsedIP == False:
            if prefix.count('.') >= 3:
                try:
                    parsedIP = ipaddress.IPv4Address(bytes(map(int, prefix.split('.')[-4 : ])))
                except:
                    pass
            if parsedIP == False:
                parsedIP = tryParseIP(prefix.split('.')[-1])
        if parsedIP == False:
            sys.stdout.write(f"Info: couldn't find an ip in '{qname}' -> '{prefix}', returning NODATA to {addr}\n")
            # Adding a SOA record turns this into a NODATA response and lets clients cache this response. IIUC.
            r.add_auth(root_RR_SOA(qname))
            sock.sendto(r.pack(), addr)
            continue

        NShostname = str(parsedIP).replace(':', LEGALCOLON) + '.' + zonename
        if isinstance(parsedIP, ipaddress.IPv4Address):
            ARType = dnslib.QTYPE.A
            ARrdata = dnslib.A(str(parsedIP))
        else:
            ARType = dnslib.QTYPE.AAAA
            ARrdata = dnslib.AAAA(str(parsedIP))

        sys.stdout.write(f'Debug: {qname} -> {NShostname} -> {str(parsedIP)} for {addr}\n')
        r.add_auth(dnslib.RR(qname, dnslib.QTYPE.NS, ttl=TTL_NS, rdata=dnslib.NS(NShostname)))
        r.add_ar(dnslib.RR(NShostname, ARType, ttl=TTL_NS, rdata=ARrdata))

        sock.sendto(r.pack(), addr)

    except Exception as e:
        # this is just one client's problem so would be Info typically, but should not happen and indicates a globally applicable bug in the software, hence warn for it happening
        sys.stderr.write(f'Warn: unexpected {type(e).__name__} on line {e.__traceback__.tb_lineno} while handling packet, ignoring packet from {addr}\n')
        # TODO should we return a FORMERR here? (Theoretically we might also have sent a response already)

