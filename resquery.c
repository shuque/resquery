/*
 * resquery.c - Query DNS using the libc resolver API (res_ninit/res_nquery)
 *
 * Usage: resquery [-4] [-6] [-v] [--timeout N] [--attempts N]
 *                 [--nameservers addr1,addr2,...] hostname
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

static struct option long_options[] = {
    {"timeout",     required_argument, NULL, 't'},
    {"attempts",    required_argument, NULL, 'a'},
    {"nameservers", required_argument, NULL, 'n'},
    {"verbose",     no_argument,       NULL, 'v'},
    {NULL,          0,                 NULL,  0 }
};

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [-4] [-6] [-v] [--timeout N] [--attempts N]\n"
        "       %*s [--nameservers addr1,addr2,...] hostname\n",
        prog, (int)strlen(prog) + 1, "");
    exit(1);
}

static void print_resolver_config(struct __res_state *res)
{
    printf("timeout:  %d seconds\n", res->retrans);
    printf("attempts: %d\n", res->retry);
    printf("nameservers: %d\n", res->nscount);
    for (int i = 0; i < res->nscount; i++) {
        char buf[INET6_ADDRSTRLEN];
        struct sockaddr_in *sa = &res->nsaddr_list[i];
        inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
        printf("  [%d] %s:%d\n", i, buf, ntohs(sa->sin_port));
    }
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

int main(int argc, char *argv[])
{
    int opt;
    int query_v4 = 0, query_v6 = 0;
    int verbose = 0;
    int timeout = -1;
    int attempts = -1;
    const char *nameservers = NULL;

    while ((opt = getopt_long(argc, argv, "46v", long_options, NULL)) != -1) {
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
        default:
            usage(argv[0]);
        }
    }

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
    if (nameservers) {
        if (parse_nameservers(&res, nameservers) < 0) {
            res_nclose(&res);
            return 1;
        }
    }

    if (verbose)
        print_resolver_config(&res);

    unsigned char answer[4096];
    int len;

    if (query_v4) {
        len = res_nquery(&res, hostname, ns_c_in, ns_t_a,
                         answer, sizeof(answer));
        if (len < 0) {
            fprintf(stderr, "A query failed for %s: %s\n",
                    hostname, hstrerror(h_errno));
        } else {
            parse_and_print(answer, len);
        }
    }

    if (query_v6) {
        len = res_nquery(&res, hostname, ns_c_in, ns_t_aaaa,
                         answer, sizeof(answer));
        if (len < 0) {
            fprintf(stderr, "AAAA query failed for %s: %s\n",
                    hostname, hstrerror(h_errno));
        } else {
            parse_and_print(answer, len);
        }
    }

    res_nclose(&res);
    return 0;
}
