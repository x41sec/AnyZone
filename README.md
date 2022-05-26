# AnyZone

Want to have a zone that is handled by to your server,
without logging into and fiddling with your domain's DNS configuration?

`10.0.2.3.anyz.one` is delegated to `10.0.2.3`

For more project information, see <https://anyz.one> or the `www.html` file.


## Technical overview

The main file is `anyzone.py`. For invocation, see `anyzone.py --help`.
Configuration is done at the top of the main file (see #1 about adding a
dedicated configuration file).
`ratelimit.py` is a standalone rate limiting library.

The code listens for incoming UDP packets, attempts to parse them as DNS, and
checks the record being requested.

To act authoritatively for the zone that we are assigned, it will respond
appropriately with SOA, A, and NS records when asked for this zone without
further subdomains.

Any subdomains, aside from `www.` if `SUPPORT_WWW` is enabled, are parsed as an
IP address. If the parsing fails, it returns a format error (FORMERR), and
otherwise it will return an NS record for the same record, plus a glued-on A or
AAAA record with the parsed IP value for IPv4 and IPv6 respectively. Further
subdomains are not considered while parsing. Any servers that ask about a
subdomain are thus redirected to simply ask this server. Even queries without
subdomain are typically forwarded because the glue seems to be ignored by
recursive resolvers queries (other than for handling the redirect itself).

The whole client packet handling is wrapped in a big try-catch to avoid
oversights turning into denial-of-service attacks (where the server crashes).


### Deployment

1. Configure the parent domain.
    - For a full domain like `anyz.one`, this means just going into the "set
      nameservers" menu at your registrar and configuring `anyz.one` as name
      and adding your IP address as glue data. The TLD (e.g. `.one`) is where
      this information will be stored at and returned from.
    - For a subdomain, you need two records:
        - `subdomain.example.org IN NS subdomain.example.org`
        - `subdomain.example.org IN A  <your server IP>` (and/or an AAAA record)
2. Install `dnslib`, e.g. using `apt install python3-dnslib`.
3. Run `anyzone.py` as specified in `--help`. You can also create a systemd
   service using the `anyzone.service` file. In the latter case, you can view
   logs live (similar to `tail -f`) by using `journalctl -fu anyzone`
4. Make sure 53/UDP is open in any firewalls you might have.
5. Test with `dig 10.1.2.3.subdomain.example.org`, optionally adding
   `@127.0.0.1` if the delegation hasn't propagated yet. If it returns an NS
   record with glued-on A pointing to `10.1.2.3` then you win!


## Security considerations

The relevant `--help` paragraph bears repeating:

> The project is pure Python and meant to handle Internet exposure, but it has
> not been audited for security. Deployment on an isolated, unimportant system,
> IP address, and domain is the recommended setup.

*The rest of this section will be about how various risks are handled. If you
want to deploy AnyZone, relevant decisions are already contained in the
configuration comments and you do not need to read this if you understood
those.*

Even if there is nothing valuable on the system or domain, we can damage other
servers. The DNS protocol is often abused for amplification attacks, and DNS
necessitates that responses are larger than queries. Somehow this is not seen
as an issue in and of itself, presumably because there is the still-worse open
resolver problem that allows requesting huge answers. Still, every functional
DNS server today will allow *some* amplification, and the only patchwork damage
control seems to be to keep state tables and rate limit clients. So that's what
AnyZone does. This can be aided by cookies or referring to TCP mode, but those
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
than a few kilo or megabytes, depending on your configured limit) but still
allows users to debug the problem. It is an open question whether this should
be replaced with a DNS error response instead, which would bring the
amplification factor up to 1 (break-even) but at least not above.

Oddly wrong queries currently get no response, such as an invalid number of
questions (for some reason DNS supports but never uses more than 1 query, even
if with A+AAAA this would make a lot of sense) or other general parsing error.
Here, too, it is an open question whether it would not be better to return a
proper DNS error, though for invalid packets the response should be ensured
to be at most request-sized.

The rate limits are applied before any `sendto()` code, to avoid being able to
bypass them.

Queries for names outside our zone are rejected (with a proper DNS response).

There is no version number in the version.bind response, and revealing that
this is an AnyZone server can be disabled altogether in the configuration.

DNSSEC is currently not supported. It requires real-time signing of records
because IPv6 has a *lot* of possible values and the author just hasn't found
the time yet. See #3.

An open question is whether the parent-level domain is at, or poses, any risk
when untrusted clients control subdomains through delegation. This is why a
throwaway domain is recommended for now (though, a subdomain of your company
website hosting illegal content is also not great).


## Contributions

Contributions are welcome and will fall under the AGPLv3 license as specified
in the `./LICENSE` file.

- Code fixes
- Documentation improvements
- Typos
- Optimizations
- Identifying bugs
- Security audits
- Descriptions of cool stuff you used this project for
- User testimonials
- Selfies with the source code
- I think this is a good place to stop


## Credits

- Many thanks to X41 D-Sec for sponsoring development time on this project.
- Paul Carnine's `dnslib` made development a whole lot easier. I thought it
  would be fairly trivial to just parse the packet in a few lines of code and
  respond with a mostly static byte array (just insert the specified IP, binary
  encoded, into the record's value), but things were not quite so simple.

