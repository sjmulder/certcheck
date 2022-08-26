#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
# include <winsock2.h>
# include <ws2tcpip.h>
#else
# include <unistd.h>
# include <netdb.h>
# include <sysexits.h>
# include <sys/types.h>
# include <sys/socket.h>
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#define PROGNAME	"certcheck"
#define VERSION		"0.1"

#ifdef _WIN32
# define sock_errno()	(WSAGetLastError())
# define EX_USAGE	64
#else
# define sock_errno()	(errno)
# define closesocket(x)	(close(x))
# define SOCKET		int
# define SOCKET_ERROR	-1
# define INVALID_SOCKET	-1
#endif

typedef char *strerror_fn(int);

static const char usage[] =
    "usage: certcheck [-V] host ...\n";
static SSL_CTX *ssl_ctx;

static const char *
strerror_wrap(strerror_fn *fn, int code)
{
	static char buf[128];
	const char *s;

	if ((s = fn(code)) && s[0])
		return s;

	snprintf(buf, sizeof(buf), "error %d", code);
	return buf;
}

static void
handle_addr(char *name, struct addrinfo *ai)
{
	int res;
	SOCKET sock;
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
		fprintf(stderr,
		    PROGNAME ": %s: %s\n",
		    name,
		    strerror_wrap((strerror_fn *)gai_strerror, res));
		goto cleanup;
	}

	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (sock == INVALID_SOCKET) {
		fprintf(stderr,
		    PROGNAME "[%s]:%s (%s): %s\n",
		    numeric, port, name,
		    strerror_wrap(strerror, sock_errno()));
		goto cleanup;
	}

	res = connect(sock, ai->ai_addr, ai->ai_addrlen);
	if (res == SOCKET_ERROR) {
		fprintf(stderr,
		    PROGNAME "[%s]:%s (%s): %s\n",
		    numeric, port, name,
		    strerror_wrap(strerror, sock_errno()));
		goto cleanup;
	}

	if (!(ssl = SSL_new(ssl_ctx))) {
		fprintf(stderr,
		    PROGNAME ": SSL_new: %s\n",
		    ERR_error_string(ERR_get_error(), NULL));
		goto cleanup;
	}

	if ((res = SSL_set_fd(ssl, sock)) != 1) {
		fprintf(stderr,
		    PROGNAME ": SSL_set_fd: %s\n",
		    ERR_error_string(ERR_get_error(), NULL));
		goto cleanup;
	}

	SSL_set_connect_state(ssl);

	if ((res = SSL_set_tlsext_host_name(ssl, name)) != 1)
		fprintf(stderr,
		    PROGNAME ": SSL_set_tlsext_host_name: %s\n",
		    ERR_error_string(ERR_get_error(), NULL));

	if ((res = SSL_do_handshake(ssl)) != 1) {
		fprintf(stderr,
		    PROGNAME ": SSL_do_handshake: %s\n",
		    ERR_error_string(SSL_get_error(ssl, res), NULL));
		goto cleanup;
	}

	if (!(cert = SSL_get_peer_certificate(ssl)))
		printf("(no certificate)");
	else if (!(date = X509_get0_notAfter(cert)))
		printf("(no date)");
	else if (ASN1_TIME_to_tm(date, &date_tm) != 1)
		printf("(bad date)");
	else {
		strftime(date_s, sizeof(date_s), "%Y-%m-%d %H:%M:%S",
		    &date_tm);
		printf("%s", date_s);
	}

	printf("\t%s\t[%s]:%s\n", name, numeric, port);

cleanup:
	if (cert)
		X509_free(cert);
	if (ssl)
		SSL_free(ssl);
	if (sock)
		closesocket(sock);
}

static void
handle_host(char *name)
{
	int res;
	struct addrinfo hints, *addrs, *addr;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((res = getaddrinfo(name, "https", &hints, &addrs))) {
		fprintf(stderr,
		    PROGNAME ": %s: %s\n",
		    name,
		    strerror_wrap((strerror_fn *)gai_strerror, res));
		return;
	}

	if (!addrs) {
		fprintf(stderr,
		    PROGNAME ": %s: lookup returned no address\n",
		    name);
		return;
	}

	for (addr = addrs; addr; addr = addr->ai_next)
		handle_addr(name, addr);

	freeaddrinfo(addrs);
}

int
main(int argc, char **argv)
{
	int i;
#ifdef _WIN32
	WSADATA wsa;
	int res;

	if ((res = WSAStartup(MAKEWORD(2, 0), &wsa)) != 0) {
		fprintf(stderr,
		    PROGNAME ": WSAStartup failed: %d\n",
		    res);
		return 1;
	}
#endif

	for (i=1; i < argc; i++)
		if (argv[i][0] != '-')
			break;
		else if (!strcmp(argv[i], "--"))
			{ i++; break; }
		else if (!strcmp(argv[i], "-V")) {
			puts("certcheck " VERSION "\n");
			return 0;
		} else {
			fprintf(stderr,
			    PROGNAME ": bad flag: %s\n%s",
			    argv[i], usage);
			return EX_USAGE;
		}

	if (i == argc) {
		fputs(usage, stderr);
		return EX_USAGE;
	}

	if (!(ssl_ctx = SSL_CTX_new(TLS_method()))) {
		fprintf(stderr,
		    PROGNAME ": %s\n",
		    ERR_error_string(ERR_get_error(), NULL));
		return 1;
	}

	for (; i  < argc; i++)
		handle_host(argv[i]);

	SSL_CTX_free(ssl_ctx);
#ifdef _WIN32
	WSACleanup();
#endif

	return 0;
}
