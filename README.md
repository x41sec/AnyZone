# AnyZone

Wanna have a zone that is handled by to your server,
without logging into and fiddling with your domain's DNS configuration?

`10.0.2.3.anyz.one` is delegated to `10.0.2.3`

For more project information, see <http://anyz.one> or the `www.html` file.


## Code structure

The main file is `anyzone.py`. For invocation and 'log' output info, see
`anyzone.py --help`.

Configuration is done at the top of the main file.

`ratelimit.py` is a standalone rate limiting library.

The code listens for incoming UDP packets, attempts to parse them as DNS, and
looks at the record being requested.

To act authoritatively for the zone that we are assigned, it will respond
appropriately with SOA, A, and NS records when asked for this zone.

Any subdomains, aside from `www.` if `SUPPORT_WWW` is enabled, are parsed as an
IP address. If the parsing fails, it returns a format error (FORMERR), and
otherwise it will return an NS record for the same record, plus a glued-on A or
AAAA record with the parsed IP value for IPv4 and IPv6 respectively. Further
subdomains are not considered while parsing. Any servers that ask about a
subdomain are thus redirected to simply ask this server. Even asking for the A
record is technically forwarded because the glue seems to be ignored by
recursive resolvers queries (other than for handling the redirect itself).

The whole client packet handling is wrapped in a big try-catch to avoid
oversights turning into denial-of-service attacks.


## Security considerations

The `--help` bears repeating:

> The project is pure Python and meant to handle Internet exposure, but it has
> not been audited for security. Deployment on an isolated, unimportant system,
> IP address, and domain is the recommended setup.

Even if there is nothing valuable on the system or domain, we can damage other
servers. The DNS protocol is often abused for amplification attacks, and DNS
necessitates that responses are larger than queries. Somehow this is not seen
as an issue in and of itself, presumably because there is the still-worse open
resolver problem that will allow very strong amplification. Nevertheless, every
DNS server today will allow *some* amplification, and the only patchwork damage
mitigation seems to be to keep state tables and rate limit clients. So that's
what we do. This can be aided by cookies or referring to TCP mode, but those
are harder to implement and the current method already renders amplification
ineffective&mdash;though at the cost of occasionally annoying any heavy users.

There is a global and a per-client rate limit, both configurable.
There is also a state table limit to prevent memory exhaustion.
Clients are informed of which limit they have exceeded. This reveals when a
client managed to "take down the server" by exceeding the global rate limit,
but this is presumed to be discoverable even if we would not helpfully tell
them.

Ideally, a server owner would be able to limit how much bandwidth their server
uses. Practically, nearly every service on the internet could be sent requests
to incur costs or make the hoster take it down and it does not seem to be
common. Thus, instead, it was chosen to return tiny UDP responses with a random
chance of 1 in N (e.g. 5) when rate limiting is triggered. This way, the
amplification factor is nearly zero after an initial burst (typically no more
than a few megabytes, depending on your configured limit) and the user can
still debug the problem and fix it. It is an open question whether this should
be replaced with a DNS error response instead, which would bring the
amplification factor up to 1 but at least not above.

Oddly wrong queries currently get no response, such as an invalid number of
questions (for some reason DNS supports but never uses more than 1 query, even
if with A+AAAA this would make a lot of sense) or other general parsing error.
Here, too, it is an open question whether it would not be better to return a
proper DNS error, though for unparseable packets the response should be ensured
to be smaller than the request.

The rate limits are applied before any `sendto()` code, to avoid being able to
bypass them.

Queries for names outside our zone are rejected (with a proper DNS response).

There is no version number in the version.bind response, and revealing that
this is an AnyZone server can be disabled altogether in the configuration.

DNSSEC is currently not supported. It requires real-time signing of records
given that IPv6 has a *lot* of possible values and the author just hasn't found
the time yet.

An open question is whether the parent-level domain would have any problems
when untrusted users control delegated zones. This is why a throwaway domain is
recommended for now (though, `some.ip.anyzone.yourcompany.example.org` hosting
illegal content is also not great).


## Contributions

Contributions are welcome!

- Code fixes
- Documentation improvements
- Typos
- Optimizations
- Security audits
- User testimonials
- Descriptions of cool stuff you used this project for
- Selfies with the source code
- I think this is a good place to stop

Your contribution(s) will fall under the AGPLv3 license as specified in the
`./LICENSE` file.

