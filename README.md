# resquery

A command-line DNS lookup tool that uses the libc resolver API directly
(`res_ninit`, `res_nsearch`, `res_nclose`), providing full programmatic
control over resolver behavior.

Unlike `getaddrinfo()`, which is subject to nsswitch.conf, NSS modules,
and system daemons like systemd-resolved or sssd, resquery talks directly
to DNS nameservers through the stub resolver, allowing precise control
over timeouts, retries, nameserver selection, search lists, and DNSSEC
options.

## Building

```sh
make
```

Or manually:

```sh
cc -Wall -Wextra -o resquery resquery.c -lresolv
```

Requires a system with glibc (Linux). The resolver API used
(`res_ninit`/`res_nsearch`) and the `__res_state` structure are
glibc-specific.

## Usage

```
resquery [-4] [-6] [-v] [--timeout N] [--attempts N]
         [--nameservers addr1,addr2,...]
         [--search dom1,dom2,...] [--ndots N]
         [--rotate] [--edns] [--tcp]
         [--dnssec] [--trustad] [--secureonly]
         hostname
```

## Options

| Option | Description |
|--------|-------------|
| `-4` | Query for A records only (IPv4) |
| `-6` | Query for AAAA records only (IPv6) |
| `-v` | Verbose: display resolver configuration and query diagnostics |
| `--timeout N` | Per-nameserver timeout in seconds (sets `res.retrans`) |
| `--attempts N` | Number of rounds through the nameserver list (sets `res.retry`) |
| `--nameservers addr1,addr2,...` | Comma-separated list of nameserver IPv4 addresses |
| `--search dom1,dom2,...` | Comma-separated list of search domains |
| `--ndots N` | Threshold for trying a name as absolute vs. appending search domains |
| `--rotate` | Round-robin through nameservers (`RES_ROTATE`) |
| `--edns` | Enable EDNS0 (`RES_USE_EDNS0`) |
| `--tcp` | Force queries over TCP (`RES_USEVC`) |
| `--dnssec` | Set the DNSSEC OK (DO) bit in queries (`RES_USE_DNSSEC`) |
| `--trustad` | Set the AD (Authenticated Data) bit in queries (`RES_TRUSTAD`) |
| `--secureonly` | Only accept responses with AD=1; implies `--trustad` |

By default (without `-4` or `-6`), both AAAA and A queries are performed,
with AAAA first.

## Examples

```sh
# Basic lookup (both AAAA and A)
./resquery www.example.com

# IPv4 only with verbose output
./resquery -4 -v www.example.com

# Custom nameservers with 1-second timeout
./resquery -v --nameservers 8.8.8.8,1.1.1.1 --timeout 1 www.example.com

# Test timeout behavior with an unreachable nameserver
./resquery -v --timeout 1 --attempts 1 --nameservers 10.7.7.7 www.example.com

# Custom search list
./resquery -v --search example.com,test.org myhost

# DNSSEC validation check
./resquery -v --secureonly www.example.com

# Force TCP, enable EDNS0
./resquery --tcp --edns www.example.com
```

## Output

IP addresses are printed one per line to stdout. With `-v`, resolver
configuration and diagnostic messages are printed with a `# ` prefix,
making it easy to filter them out:

```sh
./resquery -v www.example.com | grep -v '^#'
```

## Limitations

- Only IPv4 nameserver addresses are supported in `--nameservers`.
  IPv6 nameservers require the extended address list in `__res_state`,
  which is more complex to configure portably.
- This tool is primarily developed for Linux (glibc). The BSD variants
  (FreeBSD, NetBSD, OpenBSD) also have BIND-derived resolver routines
  in their C libraries, so much of this code may work on those platforms.
  However, some newer resolver flags like `RES_USE_DNSSEC` and
  `RES_TRUSTAD` may not be available on all BSDs. On macOS, the resolver
  API exists but goes through mDNSResponder, so direct `__res_state`
  manipulation may not have the expected effect.
