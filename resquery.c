/*
 * resquery.c - Query DNS using the libc resolver API (res_ninit/res_nsearch)
 *
 * Compile: cc -o resquery resquery.c -lresolv
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <netdb.h>
#include <resolv.h>

#define MAX_NAMESERVERS 8
#define VERSION "0.0.1"

static struct option long_options[] = {
    {"timeout",     required_argument, NULL, 't'},
    {"attempts",    required_argument, NULL, 'a'},
    {"nameservers", required_argument, NULL, 'n'},
    {"search",      required_argument, NULL, 's'},
    {"ndots",       required_argument, NULL, 'd'},
    {"rotate",      no_argument,       NULL, 'r'},
    {"edns",        no_argument,       NULL, 'e'},
    {"tcp",         no_argument,       NULL, 'T'},
    {"dnssec",      no_argument,       NULL, 'D'},
    {"trustad",     no_argument,       NULL, 'A'},
    {"secureonly",  no_argument,       NULL, 'S'},
    {"debug",       no_argument,       NULL, 'g'},
    {"verbose",     no_argument,       NULL, 'v'},
    {"help",        no_argument,       NULL, 'h'},
    {NULL,          0,                 NULL,  0 }
};

static void print_usage(FILE *fp, const char *prog)
{
    int pad = (int)strlen(prog) + 1;
    fprintf(fp,
        "Usage: %s [-4] [-6] [-v] [-h] [--timeout N] [--attempts N]\n"
        "       %*s [--nameservers addr1,addr2,...]\n"
        "       %*s [--search dom1,dom2,...] [--ndots N]\n"
        "       %*s [--rotate] [--edns] [--tcp]\n"
        "       %*s [--dnssec] [--trustad] [--secureonly]\n"
        "       %*s [--debug] hostname\n",
        prog, pad, "", pad, "", pad, "", pad, "", pad, "");
}

static void usage(const char *prog)
{
    print_usage(stderr, prog);
    exit(1);
}

static void help(const char *prog)
{
    printf("resquery %s\n", VERSION);
    print_usage(stdout, prog);
    printf(
        "\n"
        "Options:\n"
        "  -4                  Query for A records only (IPv4)\n"
        "  -6                  Query for AAAA records only (IPv6)\n"
        "  -v, --verbose       Display resolver configuration and diagnostics\n"
        "  -h, --help          Show this help message\n"
        "  --timeout N         Per-nameserver timeout in seconds\n"
        "  --attempts N        Number of rounds through the nameserver list\n"
        "  --nameservers list  Comma-separated nameserver IPv4 addresses\n"
        "  --search list       Comma-separated search domain list\n"
        "  --ndots N           Dots threshold for absolute vs. search lookup\n"
        "  --rotate            Round-robin through nameservers\n"
        "  --edns              Enable EDNS0\n"
        "  --tcp               Force queries over TCP\n"
        "  --dnssec            Set the DNSSEC OK (DO) bit in queries\n"
        "  --trustad           Set the AD (Authenticated Data) bit in queries\n"
        "  --secureonly        Only accept responses with AD=1 (implies --trustad)\n"
        "  --debug             Show each query issued during search (implies -v)\n");
    exit(0);
}

static void print_resolver_config(struct __res_state *res)
{
    printf("# timeout:  %d seconds\n", res->retrans);
    printf("# attempts: %d\n", res->retry);
    printf("# nameservers: %d\n", res->nscount);
    for (int i = 0; i < res->nscount; i++) {
        char buf[INET6_ADDRSTRLEN];
        struct sockaddr_in *sa = &res->nsaddr_list[i];
        inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
        printf("#   [%d] %s:%d\n", i, buf, ntohs(sa->sin_port));
    }
    printf("# search:");
    for (int i = 0; i < MAXDNSRCH && res->dnsrch[i]; i++)
        printf(" %s", res->dnsrch[i]);
    printf("\n");
    printf("# ndots:    %d\n", res->ndots);
    printf("# rotate:   %s\n", (res->options & RES_ROTATE) ? "yes" : "no");
    printf("# edns0:    %s\n", (res->options & RES_USE_EDNS0) ? "yes" : "no");
    printf("# tcp:      %s\n", (res->options & RES_USEVC) ? "yes" : "no");
    printf("# recurse:  %s\n", (res->options & RES_RECURSE) ? "yes" : "no");
    printf("# stayopen: %s\n", (res->options & RES_STAYOPEN) ? "yes" : "no");
    printf("# defnames: %s\n", (res->options & RES_DEFNAMES) ? "yes" : "no");
    printf("# dnsrch:   %s\n", (res->options & RES_DNSRCH) ? "yes" : "no");
    printf("# snglkup:  %s\n", (res->options & RES_SNGLKUP) ? "yes" : "no");
    printf("# snglkupreop: %s\n", (res->options & RES_SNGLKUPREOP) ? "yes" : "no");
    printf("# dnssec:   %s\n", (res->options & RES_USE_DNSSEC) ? "yes" : "no");
    printf("# trustad:  %s\n", (res->options & RES_TRUSTAD) ? "yes" : "no");
    printf("\n");
}

static int parse_nameservers(struct __res_state *res, const char *arg)
{
    char buf[1024];
    int count = 0;

    strncpy(buf, arg, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *token = strtok(buf, ",");
    while (token && count < MAX_NAMESERVERS) {
        while (*token == ' ') token++;

        struct sockaddr_in sa4;
        struct sockaddr_in6 sa6;

        if (inet_pton(AF_INET, token, &sa4.sin_addr) == 1) {
            sa4.sin_family = AF_INET;
            sa4.sin_port = htons(53);
            res->nsaddr_list[count] = sa4;
            count++;
        } else if (inet_pton(AF_INET6, token, &sa6.sin6_addr) == 1) {
            /* IPv6 nameservers require the extended nsaddr list;
               for simplicity, only IPv4 nameservers are supported here */
            fprintf(stderr, "Warning: IPv6 nameserver %s not supported, "
                    "skipping\n", token);
        } else {
            fprintf(stderr, "Invalid nameserver address: %s\n", token);
            return -1;
        }

        token = strtok(NULL, ",");
    }

    if (count == 0) {
        fprintf(stderr, "No valid nameservers specified\n");
        return -1;
    }

    res->nscount = count;
    return 0;
}

static void parse_and_print(const unsigned char *answer, int anslen)
{
    ns_msg msg;
    ns_rr rr;

    if (ns_initparse(answer, anslen, &msg) < 0) {
        perror("ns_initparse");
        return;
    }

    int ancount = ns_msg_count(msg, ns_s_an);

    for (int i = 0; i < ancount; i++) {
        if (ns_parserr(&msg, ns_s_an, i, &rr) < 0) {
            perror("ns_parserr");
            continue;
        }

        int rrtype = ns_rr_type(rr);
        const unsigned char *rdata = ns_rr_rdata(rr);
        char buf[INET6_ADDRSTRLEN];

        if (rrtype == ns_t_a && ns_rr_rdlen(rr) == 4) {
            inet_ntop(AF_INET, rdata, buf, sizeof(buf));
            printf("%s\n", buf);
        } else if (rrtype == ns_t_aaaa && ns_rr_rdlen(rr) == 16) {
            inet_ntop(AF_INET6, rdata, buf, sizeof(buf));
            printf("%s\n", buf);
        }
    }
}

static int count_dots(const char *name)
{
    int dots = 0;
    for (const char *p = name; *p; p++)
        if (*p == '.')
            dots++;
    return dots;
}

/*
 * Local reimplementation of res_nsearch() that prints each query
 * issued during search list processing. This is intended for
 * debugging only; the normal code path uses the real res_nsearch()
 * from libresolv to guarantee identical behavior to the system.
 *
 * Search logic (matching glibc behavior):
 *   - If name ends with '.', query as-is (absolute) and return.
 *   - If dots in name >= ndots, try as-is first.
 *   - Try each domain in the search list.
 *   - If dots in name >= ndots and search list failed, use the
 *     as-is result. Otherwise try as-is as a last resort.
 *   - h_errno is set from the most relevant failure.
 */
static int res_nsearch_debug(struct __res_state *res, const char *name,
                          int class, int type, const char *type_string,
                          unsigned char *answer, int anslen)
{
    char qname[NS_MAXDNAME];
    int len;
    int dots = count_dots(name);
    int trailing_dot = (name[0] != '\0' && name[strlen(name) - 1] == '.');
    int tried_as_is = 0;
    int saved_herrno = -1;
    int got_nodata = 0;

    /* Trailing dot: treat as absolute, no search */
    if (trailing_dot) {
        fprintf(stderr, "# debug: query %s %s (absolute, trailing dot)\n",
                name, type_string);
        return res_nquery(res, name, class, type, answer, anslen);
    }

    /* If name has enough dots, try as-is first */
    if (dots >= res->ndots) {
        fprintf(stderr, "# debug: query %s %s (as-is, dots=%d >= ndots=%d)\n",
                name, type_string, dots, res->ndots);
        len = res_nquery(res, name, class, type, answer, anslen);
        if (len >= 0)
            return len;
        tried_as_is = 1;
        saved_herrno = h_errno;
        if (h_errno == NO_DATA)
            got_nodata = 1;
        /* If name has a dot and we got an authoritative NXDOMAIN,
           don't bother with the search list */
        if (dots > 0 && h_errno == HOST_NOT_FOUND)
            return -1;
    }

    /* Try appending each search domain */
    if (res->options & RES_DNSRCH) {
        for (int i = 0; i < MAXDNSRCH && res->dnsrch[i]; i++) {
            int n = snprintf(qname, sizeof(qname), "%s.%s",
                             name, res->dnsrch[i]);
            if (n < 0 || (size_t)n >= sizeof(qname))
                continue;
            fprintf(stderr, "# debug: query %s %s (search: +%s)\n",
                    qname, type_string, res->dnsrch[i]);
            len = res_nquery(res, qname, class, type, answer, anslen);
            if (len >= 0)
                return len;
            if (h_errno == NO_DATA)
                got_nodata = 1;
            /* Stop searching on authoritative NXDOMAIN only if
               the search domain itself could be valid */
        }
    }

    /* If we haven't tried as-is yet, try now as last resort */
    if (!tried_as_is) {
        fprintf(stderr, "# debug: query %s %s (as-is, last resort)\n",
                name, type_string);
        len = res_nquery(res, name, class, type, answer, anslen);
        if (len >= 0)
            return len;
    } else {
        /* Restore h_errno from the as-is query */
        h_errno = saved_herrno;
    }

    /* If any query got NODATA, prefer that over HOST_NOT_FOUND */
    if (got_nodata)
        h_errno = NO_DATA;

    return -1;
}

static void do_query(struct __res_state *res, const char *hostname,
                     int rrtype, const char *rrtype_string, int verbose,
                     int debug, int check_ad, int secureonly)
{
    unsigned char answer[4096];
    int len;

    if (debug)
        len = res_nsearch_debug(res, hostname, ns_c_in, rrtype,
                             rrtype_string, answer, sizeof(answer));
    else
        len = res_nsearch(res, hostname, ns_c_in, rrtype,
                          answer, sizeof(answer));
    if (len < 0) {
        /* Note: the answer buffer is unreliable here because
           res_nsearch() overwrites it with each query during
           search list iteration. So, we only use h_errno
           instead, which is correctly restored from the
           originally relevant query. */
        if (verbose)
            fprintf(stderr, "# %s query failed for %s: %s\n",
                    rrtype_string, hostname, hstrerror(h_errno));
        return;
    }

    HEADER *hp = (HEADER *)answer;
    if (verbose) {
        printf("# %s response:", rrtype_string);
        if (check_ad)
            printf(" AD=%d (%s)", hp->ad, hp->ad ? "secure" : "insecure");
        printf("\n");
    }
    if (secureonly && !hp->ad) {
        if (verbose)
            fprintf(stderr, "# %s response for %s is insecure, "
                    "discarding\n", rrtype_string, hostname);
    } else {
        parse_and_print(answer, len);
    }
}

int main(int argc, char *argv[])
{
    int opt;
    int query_v4 = 0, query_v6 = 0;
    int verbose = 0, debug = 0;
    int timeout = -1;
    int attempts = -1;
    const char *nameservers = NULL;
    const char *search = NULL;
    int ndots = -1;
    int rotate = 0;
    int edns = 0;
    int tcp = 0;
    int dnssec = 0;
    int trustad = 0;
    int secureonly = 0;

    while ((opt = getopt_long(argc, argv, "46vh", long_options, NULL)) != -1) {
        switch (opt) {
        case '4':
            query_v4 = 1;
            break;
        case '6':
            query_v6 = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        case 't':
            timeout = atoi(optarg);
            break;
        case 'a':
            attempts = atoi(optarg);
            break;
        case 'n':
            nameservers = optarg;
            break;
        case 's':
            search = optarg;
            break;
        case 'd':
            ndots = atoi(optarg);
            break;
        case 'r':
            rotate = 1;
            break;
        case 'e':
            edns = 1;
            break;
        case 'T':
            tcp = 1;
            break;
        case 'D':
            dnssec = 1;
            break;
        case 'A':
            trustad = 1;
            break;
        case 'S':
            secureonly = 1;
            break;
        case 'g':
            debug = 1;
            break;
        case 'h':
            help(argv[0]);
            break;
        default:
            usage(argv[0]);
        }
    }

    if (secureonly && !trustad)
        trustad = 1;
    if (debug && !verbose)
        verbose = 1;

    if (optind >= argc)
        usage(argv[0]);

    const char *hostname = argv[optind];

    /* Default: query both A and AAAA */
    if (!query_v4 && !query_v6) {
        query_v4 = 1;
        query_v6 = 1;
    }

    /* Initialize resolver state */
    struct __res_state res;
    memset(&res, 0, sizeof(res));

    if (res_ninit(&res) < 0) {
        fprintf(stderr, "res_ninit failed\n");
        return 1;
    }

    if (timeout > 0)
        res.retrans = timeout;
    if (attempts > 0)
        res.retry = attempts;
    if (ndots >= 0)
        res.ndots = ndots;
    if (rotate)
        res.options |= RES_ROTATE;
    if (edns)
        res.options |= RES_USE_EDNS0;
    if (tcp)
        res.options |= RES_USEVC;
    if (dnssec)
        res.options |= RES_USE_DNSSEC;
    if (trustad)
        res.options |= RES_TRUSTAD;
    if (nameservers) {
        if (parse_nameservers(&res, nameservers) < 0) {
            res_nclose(&res);
            return 1;
        }
    }
    if (search) {
        /* Clear existing search list and set from comma-separated arg */
        for (int i = 0; i < MAXDNSRCH; i++)
            res.dnsrch[i] = NULL;
        res.defdname[0] = '\0';
        strncpy(res.defdname, search, sizeof(res.defdname) - 1);
        res.defdname[sizeof(res.defdname) - 1] = '\0';
        int idx = 0;
        char *p = res.defdname;
        while (*p && idx < MAXDNSRCH) {
            while (*p == ' ' || *p == ',') p++;
            if (*p == '\0') break;
            res.dnsrch[idx++] = p;
            while (*p && *p != ',' && *p != ' ') p++;
            if (*p) *p++ = '\0';
        }
    }

    if (verbose)
        print_resolver_config(&res);

    int check_ad = dnssec || trustad;

    if (query_v6)
        do_query(&res, hostname, ns_t_aaaa, "AAAA", verbose, debug,
                 check_ad, secureonly);
    if (query_v4)
        do_query(&res, hostname, ns_t_a, "A", verbose, debug,
                 check_ad, secureonly);

    res_nclose(&res);
    return 0;
}
