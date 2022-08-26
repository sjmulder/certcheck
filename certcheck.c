#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <unistd.h>
#include <getopt.h>
#include <netdb.h>
#include <sysexits.h>
#include <err.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "config.h"

static const char usage[] =
"usage: certcheck [-V] host ...\n";

static SSL_CTX *ssl_ctx;

static void
warn_ssl(long code, char *fmt, ...)
{
	va_list ap;
	char buf[512];

	if (fmt) {
		va_start(ap, fmt);
		vsnprintf(buf, sizeof(buf), fmt, ap);
		va_end(ap);

		warnx("%s: %s", buf, ERR_error_string(code, NULL));
	} else
		warnx("%s", ERR_error_string(code, NULL));
}

static void
handle_addr(char *name, struct addrinfo *ai)
{
	int res, sock=0;
	char numeric[128], port[16];
	SSL *ssl=NULL;
	X509 *cert=NULL;
	const ASN1_TIME *date;
	struct tm date_tm;
	char date_s[128];

	res = getnameinfo(
	    ai->ai_addr, ai->ai_addrlen,
	    numeric, sizeof(numeric),
	    port, sizeof(port),
	    NI_NUMERICHOST | NI_NUMERICSERV);
	if (res) {
		warnx("%s: %s\n", name, gai_strerror(res));
		goto cleanup;
	}

	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (sock == -1) {
		warn("[%s]:%s (%s)", numeric, port, name);
		goto cleanup;
	}

	if ((res = connect(sock, ai->ai_addr, ai->ai_addrlen)) == -1) {
		warn("[%s]:%s (%s)", numeric, port, name);
		goto cleanup;
	}

	if (!(ssl = SSL_new(ssl_ctx))) {
		warn_ssl(ERR_get_error(), "SSL_new");
		goto cleanup;
	}

	if ((res = SSL_set_fd(ssl, sock)) != 1) {
		warn_ssl(SSL_get_error(ssl, res), "SSL_set_fd");
		goto cleanup;
	}

	SSL_set_connect_state(ssl);

	if ((res = SSL_set_tlsext_host_name(ssl, name)) != 1)
		warn_ssl(SSL_get_error(ssl, res),
		    "SSL_ste_tlsext_host_name");

	if ((res = SSL_do_handshake(ssl)) != 1) {
		warn_ssl(SSL_get_error(ssl, res), "SSL_do_handshake");
		goto cleanup;
	}

	if (!(cert = SSL_get_peer_certificate(ssl)))
		printf("(no certificate)");
	else if (!(date = X509_get0_notAfter(cert)))
		printf("(no date)");
	else if (ASN1_TIME_to_tm(date, &date_tm) != 1)
		printf("(bad date)");
	else {
		strftime(date_s, sizeof(date_s), "%F %T", &date_tm);
		printf("%s", date_s);
	}

	printf("\t%s\t[%s]:%s\n", name, numeric, port);

cleanup:
	if (cert)
		X509_free(cert);
	if (ssl)
		SSL_free(ssl);
	if (sock)
		close(sock);
}

static void
handle_host(char *name)
{
	int ret;
	struct addrinfo hints, *addrs, *addr;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((ret = getaddrinfo(name, "https", &hints, &addrs))) {
		warnx("%s: %s", name, gai_strerror(ret));
		return;
	}

	if (!addrs) {
		warnx("%s: lookup returned no address", name);
		return;
	}

	for (addr = addrs; addr; addr = addr->ai_next)
		handle_addr(name, addr);

	freeaddrinfo(addrs);
}

int
main(int argc, char **argv)
{
	int i,c;

	while ((c = getopt(argc, argv, "Vt:")) != -1)
		switch (c) {
		case 'V':
			puts("certcheck " VERSION "\n");
			return 0;
		default:
			fputs(usage, stderr);
			return EX_USAGE;
		}

	if (optind == argc) {
		fputs(usage, stderr);
		return EX_USAGE;
	}

	if (!(ssl_ctx = SSL_CTX_new(TLS_method()))) {
		warn_ssl(ERR_get_error(), NULL);
		return 1;
	}

	for (i = optind; i  < argc; i++)
		handle_host(argv[i]);

	SSL_CTX_free(ssl_ctx);

	return 0;
}

