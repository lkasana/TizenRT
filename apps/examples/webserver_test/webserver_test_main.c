/****************************************************************************
 *
 * Copyright 2021 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/
/**
* @brief               To send HTTP request messages and receive response messages.
*                      supported methods: GET, POST, PUT, DELETE
*                      Entity and encoding are needed only for POST and PUT methods. If an encoding is not for "C", it always uses the content-length.
* @scenario            1. Start webserver at TASH using the command "webserver start". Refer to webserver_main.c to run HTTP server.
*                      2. Start webserver_test at TASH using the command "webserver_test GET http://[serverip]/".
*
*****************************************************************************/
#include <tinyara/config.h>
#include <tinyara/compiler.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
//#include <string.h>

#ifdef CONFIG_NET_LWIP_NETDB
#include <netdb.h>
#endif
#include <arpa/inet.h>
#include <netinet/in.h>

#include <tinyara/version.h>
#include <netutils/netlib.h>

#include "../../../external/webserver/http_string_util.h"
#include "../../../external/webserver/http_client.h"
#include <protocols/webserver/http_err.h>
#include <protocols/webclient.h>


#define MBED_DEBUG_LEVEL 5
#define WEBSERVER_TEST_BUF_SIZE     4600

#define WGET_OK                    0
#define WGET_ERR                   -1
#define WGET_MSG_CONSTRUCT_ERR     -2
#define WGET_SOCKET_CONNECT_ERR    -3

#define HTTPSTATUS_NONE            0
#define HTTPSTATUS_OK              1
#define HTTPSTATUS_MOVED           2
#define HTTPSTATUS_ERROR           3

#define ISO_nl                     0x0a
#define ISO_cr                     0x0d
#define ISO_space                  0x20

#define prnt(...) \
	do { \
		printf("[WS_TEST]%s():%d: ", __func__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
	} while(0)


struct ws_test_wget_s {
	/* Internal status */
	uint8_t state;
	uint8_t httpstatus;
	uint16_t port; /* The port number to use in the connection */
	/* These describe the just-received buffer of data */
	FAR
	char *buffer; /* user-provided buffer */
	int buflen; /* Length of the user provided buffer */
	int offset; /* Offset to the beginning of interesting data */
	int datend; /* Offset+1 to the last valid byte of data in the buffer */
	/* Buffer HTTP header data and parse line at a time */
	char line[CONFIG_WEBCLIENT_MAXHTTPLINE];
	int ndx;
#ifdef CONFIG_WEBCLIENT_GETMIMETYPE
	char mimetype[CONFIG_WEBCLIENT_MAXMIMESIZE];
#endif
	char hostname[CONFIG_WEBCLIENT_MAXHOSTNAME];
	char filename[CONFIG_WEBCLIENT_MAXFILENAME];
};


static const char g_http10[] = "HTTP/1.0";
static const char g_http11[] = "HTTP/1.1";
#ifdef CONFIG_WEBCLIENT_GETMIMETYPE
static const char g_httpcontenttype[] = "content-type: ";
#endif
static const char g_httphost[] = "host: ";
//static const char g_httplocation[] = "location: ";
static const char g_httpget[] = "GET ";
static const char g_httppost[] = "POST ";
static const char g_httpput[] = "PUT ";
static const char g_httpdelete[] = "DELETE ";
static const char g_http200[] = "200 ";

static const char g_httpcrnl[] = "\r\n";

static const char g_httpform[] = "Content-Type: application/x-www-form-urlencoded";
static const char g_httpcontsize[] = "Content-Length: ";
static const char g_httpchunked[] = "Transfer-Encoding: chunked";
static const char *tlsname = "ws_test_tls_client";	//TODO original "araweb_tls_client"


static int g_https;
static int g_is_test_entity;
static const char headerfield_connect[] = "Connection";
static const char headerfield_close[] = "close";
static const char headerfield_useragent[] = "User-Agent";
static const char headerfield_tinyara[] = "TinyARA";


static const char c_ca_crt_rsa[] =
	"-----BEGIN CERTIFICATE-----\r\n"
	"MIICCTCCAa+gAwIBAgIUAnGePchUCuPITm/qbJFVmLDJHJ4wCgYIKoZIzj0EAwIw\r\n"
	"ejELMAkGA1UEBhMCWFgxDDAKBgNVBAgMA04vQTEMMAoGA1UEBwwDTi9BMSAwHgYD\r\n"
	"VQQKDBdTZWxmLXNpZ25lZCBjZXJ0aWZpY2F0ZTEtMCsGA1UEAwwkMTkyLjE2OC4x\r\n"
	"LjM6IFNlbGYtc2lnbmVkIGNlcnRpZmljYXRlMB4XDTIxMTEwMjA4NDkzNFoXDTIy\r\n"
	"MTEwMjA4NDkzNFowejELMAkGA1UEBhMCWFgxDDAKBgNVBAgMA04vQTEMMAoGA1UE\r\n"
	"BwwDTi9BMSAwHgYDVQQKDBdTZWxmLXNpZ25lZCBjZXJ0aWZpY2F0ZTEtMCsGA1UE\r\n"
	"AwwkMTkyLjE2OC4xLjM6IFNlbGYtc2lnbmVkIGNlcnRpZmljYXRlMFkwEwYHKoZI\r\n"
	"zj0CAQYIKoZIzj0DAQcDQgAEMQGxBKIZVO56Mcjzbaks5GkFhxnAh7fEL+CIcHcN\r\n"
	"Po6/sC90wwVVvjka9JPk2/WEm7tXaXBAWghWXRP++bgtf6MTMBEwDwYDVR0RBAgw\r\n"
	"BocEwKgBAzAKBggqhkjOPQQDAgNIADBFAiAPfF0ktFn0hgaV+67Jy4EYo24UIcR0\r\n"
	"jn5h4mLRDLo+8QIhAP8XARyV6OBYeC6sginpnUT72LpI8K4sP/An66jmnIAJ\r\n"
	"-----END CERTIFICATE-----\r\n";

static struct http_client_ssl_config_t g_ssl_config = {
	(char *)c_ca_crt_rsa, NULL, NULL,
	sizeof(c_ca_crt_rsa), 0, 0, WEBCLIENT_SSL_VERIFY_REQUIRED
};


//TODO fix as per ours format
static void ws_test_dump_usage(void)
{
	printf("\n  webserver_test usage:\n");
	printf("   $ webserver_test <method> <uri> [options...] \n");
	printf("\n");
	printf(" <method>   : %%s (GET, PUT, POST, DELETE)\n");
	printf(" <uri>      : %%s (Host address : should be started with http:// or https://)\n");
	printf("\n [options...] \n");
	printf(" chunked=1             Enable chunked encoding (default is disabled)\n");
	printf(" entity=DATA           Set entity data (default is NULL)\n");
	printf(" test_entity=SIZE      Test entity size (default is 0)\n");
	printf("\n  example:\n");
	printf("   $ webserver_test GET https://127.0.0.1/\n");
	printf("   $ webserver_test GET https://127.0.0.1/ async=1 entity=data\n");
}

static char* ws_test_wget_strcpy(char *dest, const char *src, struct http_client_request_t *ws)
{
	int len = strlen(src);

	if (dest + len - ws->buffer >= ws->buflen) {
		prnt("Error: buffer is too small");
		return NULL;
	}

	memcpy(dest, src, len);
	dest[len] = '\0';
	return dest + len;
}

static char* ws_test_wget_strlencpy(char *dest, const char *src, int len, struct http_client_request_t *ws)
{
	if (dest + len - ws->buffer >= ws->buflen) {
		prnt("Error: buffer is too small");
		return NULL;
	}

	memcpy(dest, src, len);
	dest[len] = '\0';
	return dest + len;
}

static char* ws_test_wget_chunksize(char *dest, int len, struct http_client_request_t *ws)
{
	char size[10] = {0,};

	if (!dest) {
		return NULL;
	}

	snprintf(size, sizeof(size), "%x", len);
	len = strlen(size);
	if (dest + len - ws->buffer >= ws->buflen) {
		prnt("Error: buffer is too small");
		return NULL;
	}
	memcpy(dest, size, len);
	return dest + len;
}



int ws_test_http_client_response_init(struct http_client_response_t *response)
{
	response->phrase = malloc(WEBCLIENT_CONF_MAX_PHRASE_SIZE);
	if (response->phrase == NULL) {
		prnt("Error: Fail to init");
		return -1;
	}
	response->message = malloc(WEBCLIENT_CONF_MAX_MESSAGE_SIZE);
	if (response->message == NULL) {
		prnt("Error: Fail to init");
		free(response->phrase);
		return -1;
	}
	response->headers = malloc(sizeof(struct http_keyvalue_list_t));
	if (response->headers == NULL || http_keyvalue_list_init(response->headers) < 0) {
		prnt("Error: Fail to init");
		free(response->phrase);
		free(response->message);
		return -1;
	}
	return 0;
}

void ws_test_http_client_response_release(struct http_client_response_t *response)
{
	free(response->phrase);
	free(response->message);
	http_keyvalue_list_release(response->headers);
	free(response->headers);
}

static int ws_test_wget_gethostip(FAR char *hostname, in_addr_t *ipv4addr)
{
#ifdef CONFIG_NET_LWIP_NETDB
	FAR struct hostent *he;
	he = gethostbyname(hostname);
	if (he == NULL) {
		prnt("gethostbyname failed");
		return -ENOENT;
	} else if (he->h_addrtype != AF_INET) {
		prnt("gethostbyname returned an address of type: %d", he->h_addrtype);
		return -ENOEXEC;
	}

	memcpy(ipv4addr, he->h_addr, sizeof(in_addr_t));
	return OK;
#else
	prnt("NETDB is not supported");
	return ERROR;
#endif
}


#ifdef CONFIG_NET_SECURITY_TLS
static void ws_test_wget_tls_debug(void *ctx, int level, const char *file, int line, const char *str)
{
	printf("%s:%04d: %s", file, line, str);
}

static void ws_test_wget_tls_release(struct http_client_tls_t *client)
{
	if (client == NULL) {
		return;
	}

	mbedtls_x509_crt_free(&(client->tls_rootca));
	mbedtls_x509_crt_free(&(client->tls_clicert));
	mbedtls_pk_free(&(client->tls_pkey));
	mbedtls_ssl_config_free(&(client->tls_conf));
	mbedtls_ctr_drbg_free(&(client->tls_ctr_drbg));
	mbedtls_entropy_free(&(client->tls_entropy));
	mbedtls_ssl_session_free(&(client->tls_session));
}

int ws_test_webclient_tls_init(struct http_client_tls_t *client, struct http_client_ssl_config_t *ssl_config)
{
	int result = 0;

	if (!client || !ssl_config) {
		return -1;
	}

	mbedtls_ssl_config_init(&(client->tls_conf));
	mbedtls_x509_crt_init(&(client->tls_rootca));
	mbedtls_x509_crt_init(&(client->tls_clicert));
	mbedtls_pk_init(&(client->tls_pkey));
	mbedtls_entropy_init(&(client->tls_entropy));
	mbedtls_ctr_drbg_init(&(client->tls_ctr_drbg));
	mbedtls_ssl_session_init(&(client->tls_session));
	mbedtls_ssl_conf_authmode(&(client->tls_conf), ssl_config->auth_mode);
#ifdef MBEDTLS_DEBUG_C
	mbedtls_debug_set_threshold(MBED_DEBUG_LEVEL);
#endif

	/* 0. Initialize the RNG */
	prnt("  . Seeding the random number generator...");

	if ((result = mbedtls_ctr_drbg_seed(&(client->tls_ctr_drbg), mbedtls_entropy_func, &(client->tls_entropy), (const unsigned char *)tlsname, strlen(tlsname))) != 0) {
		prnt("Error: mbedtls_ctr_drbg_seed returned -%4x", -result);
		goto TLS_INIT_EXIT;
	}

	prnt("Ok");

	/* 1. Setup ssl stuff */
	prnt("  . Setting up the SSL data...");

	if ((result = mbedtls_ssl_config_defaults(&(client->tls_conf),
				  MBEDTLS_SSL_IS_CLIENT,
				  MBEDTLS_SSL_TRANSPORT_STREAM,
				  MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		prnt("Error: mbedtls_ssl_config_defaults returned -%4x", -result);
		goto TLS_INIT_EXIT;
	}

	mbedtls_ssl_conf_rng(&(client->tls_conf), mbedtls_ctr_drbg_random,
						 &(client->tls_ctr_drbg));
	mbedtls_ssl_conf_dbg(&(client->tls_conf), ws_test_wget_tls_debug, stdout);

	prnt("Ok");

	if (ssl_config->dev_cert && ssl_config->private_key) {
		/* 2. Load the certificates and private key */

		prnt("  . Loading the client cert. and key...");

		if ((result = mbedtls_x509_crt_parse(&(client->tls_clicert),
											 (const unsigned char *)ssl_config->dev_cert,
											 ssl_config->dev_cert_len)) != 0) {
			prnt("Error: cli_cert parse fail, returned -%4x", -result);
			goto TLS_INIT_EXIT;
		}

		if ((result = mbedtls_pk_parse_key(&(client->tls_pkey),
										   (const unsigned char *)ssl_config->private_key,
										   ssl_config->private_key_len, NULL, 0)) != 0) {
			prnt("Error: cli_key parse fail, returned -%4x", -result);
			goto TLS_INIT_EXIT;
		}

		if ((result = mbedtls_ssl_conf_own_cert(&(client->tls_conf),
												&(client->tls_clicert),
												&(client->tls_pkey))) != 0) {
			prnt("Error: mbedtls_ssl_conf_own_cert returned -%4x", -result);
			goto TLS_INIT_EXIT;
		}

		prnt("Ok");
	}

	if (ssl_config->root_ca) {

		/* 3. Load the CA certificate */
		prnt("  . Loading the CA cert...");

		if ((result = mbedtls_x509_crt_parse(&(client->tls_rootca),
											 (const unsigned char *)ssl_config->root_ca,
											 ssl_config->root_ca_len)) != 0) {
			prnt("Error: CA_cert parse fail, returned -%4x", -result);
			goto TLS_INIT_EXIT;
		}

		/* CA cert may be first or second in chain depending if client cert was loaded */
		mbedtls_ssl_conf_ca_chain(&(client->tls_conf), &(client->tls_rootca), NULL);

		prnt("Ok");
	}

	return 0;
TLS_INIT_EXIT:
	ws_test_wget_tls_release(client);
	return result;
}

void ws_test_wget_tls_ssl_release(struct http_client_tls_t *client)
{
	if (client == NULL) {
		return;
	}

	mbedtls_net_free(&(client->tls_client_fd));
	mbedtls_ssl_session_reset(&(client->tls_ssl));
	mbedtls_ssl_free(&(client->tls_ssl));
}

int ws_test_wget_tls_handshake(struct http_client_tls_t *client, const char *hostname)
{
	int result = 0;

	mbedtls_net_init(&(client->tls_client_fd));
	mbedtls_ssl_init(&(client->tls_ssl));

	client->tls_client_fd.fd = client->client_fd;

	if (mbedtls_net_set_block(&(client->tls_client_fd)) < 0) {
		prnt("Error: mbedtls_net_set_block fail");
		goto HANDSHAKE_FAIL;
	}

	prnt("TLS Init Success");

	if ((result = mbedtls_ssl_setup(&(client->tls_ssl),
									&(client->tls_conf))) != 0) {
		prnt("Error: mbedtls_ssl_setup returned -%4x", -result);
		goto HANDSHAKE_FAIL;
	}

	/*
	 * Server name intication is an extension to the TLS networking protocol
	 * If server presents multiple certificates on the same IP address,
	 * client could make multiple secure session depends on hostname.
	 *
	 * Note : Hostname in TLS is a subject's common name(CN) of certificates.
	 */
#if WEBCLIENT_CONF_CHECK_TLS_HOSTNAME
	if ((result = mbedtls_ssl_set_hostname(&(client->tls_ssl), hostname)) != 0) {
		prnt("Error: mbedtls_hostname returned -%4x", -result);
		goto HANDSHAKE_FAIL;
	}
#endif

	mbedtls_ssl_set_bio(&(client->tls_ssl), &(client->tls_client_fd),
						mbedtls_net_send, mbedtls_net_recv, NULL);

	/* Handshake */
	while ((result = mbedtls_ssl_handshake(&(client->tls_ssl))) != 0) {
		if (result != MBEDTLS_ERR_SSL_WANT_READ &&
			result != MBEDTLS_ERR_SSL_WANT_WRITE) {
			prnt("Error: TLS Handshake fail returned -%4x", -result);
			goto HANDSHAKE_FAIL;
		}
	}

	prnt("TLS Handshake Success");

	return 0;
HANDSHAKE_FAIL:
	return result;
}
#endif

static int ws_test_wget_msg_construct(char *buf, struct http_client_request_t *param, struct ws_test_wget_s *ws)
{
	int post_len;
	char *dest = buf;
	char post_size[8];
	struct http_keyvalue_t *cur = NULL;

	/* Send method */
	if (param->method == WGET_MODE_GET) {
		dest = ws_test_wget_strcpy(dest, g_httpget, param);
	} else if (param->method == WGET_MODE_POST) {
		dest = ws_test_wget_strcpy(dest, g_httppost, param);
	} else if (param->method == WGET_MODE_PUT) {
		dest = ws_test_wget_strcpy(dest, g_httpput, param);
	} else if (param->method == WGET_MODE_DELETE) {
		dest = ws_test_wget_strcpy(dest, g_httpdelete, param);
	}

	if (dest == NULL) {
		return WGET_MSG_CONSTRUCT_ERR;
	}

	dest = ws_test_wget_strcpy(dest, ws->filename, param);
	if (dest == NULL) {
		return WGET_MSG_CONSTRUCT_ERR;
	}

	*dest++ = ISO_space;
	dest = ws_test_wget_strcpy(dest, g_http11, param);
	if (dest == NULL) {
		return WGET_MSG_CONSTRUCT_ERR;
	}
	dest = ws_test_wget_strcpy(dest, g_httpcrnl, param);
	if (dest == NULL) {
		return WGET_MSG_CONSTRUCT_ERR;
	}
	dest = ws_test_wget_strcpy(dest, g_httphost, param);
	if (dest == NULL) {
		return WGET_MSG_CONSTRUCT_ERR;
	}
	dest = ws_test_wget_strcpy(dest, ws->hostname, param);
	if (dest == NULL) {
		return WGET_MSG_CONSTRUCT_ERR;
	}
	dest = ws_test_wget_strcpy(dest, g_httpcrnl, param);
	if (dest == NULL) {
		return WGET_MSG_CONSTRUCT_ERR;
	}

	/* header of entity */

	if (param->method == WGET_MODE_POST || param->method == WGET_MODE_PUT) {
		/* Look for Content-Type in the headers */
		cur = param->headers->head->next;
		while (cur != param->headers->tail) {
			if (!strncmp(cur->key, "Content-Type", strlen("Content-Type"))) {
				break;
			}
			cur = cur->next;
		}

		/* Add default Content-Type if not found in headers */
		if (cur == param->headers->tail) {
			dest = ws_test_wget_strcpy(dest, g_httpform, param);
			if (dest == NULL) {
				return WGET_MSG_CONSTRUCT_ERR;
			}
			dest = ws_test_wget_strcpy(dest, g_httpcrnl, param);
			if (dest == NULL) {
				return WGET_MSG_CONSTRUCT_ERR;
			}
		}

		/* content length */

		if (!param->encoding) {
			dest = ws_test_wget_strcpy(dest, g_httpcontsize, param);
			if (dest == NULL) {
				return WGET_MSG_CONSTRUCT_ERR;
			}
			post_len = strlen((char *)param->entity);
			sprintf(post_size, "%d", post_len);
			dest = ws_test_wget_strcpy(dest, post_size, param);
			if (dest == NULL) {
				return WGET_MSG_CONSTRUCT_ERR;
			}
			dest = ws_test_wget_strcpy(dest, g_httpcrnl, param);
			if (dest == NULL) {
				return WGET_MSG_CONSTRUCT_ERR;
			}
		}

		/* chuncked param->encoding */

		else {
			dest = ws_test_wget_strcpy(dest, g_httpchunked, param);
			if (dest == NULL) {
				return WGET_MSG_CONSTRUCT_ERR;
			}
			dest = ws_test_wget_strcpy(dest, g_httpcrnl, param);
			if (dest == NULL) {
				return WGET_MSG_CONSTRUCT_ERR;
			}
		}
	}

	cur = param->headers->head->next;
	while (cur != param->headers->tail) {
		dest = ws_test_wget_strcpy(dest, cur->key, param);
		if (dest == NULL) {
			return WGET_MSG_CONSTRUCT_ERR;
		}
		dest = ws_test_wget_strcpy(dest, ": ", param);
		if (dest == NULL) {
			return WGET_MSG_CONSTRUCT_ERR;
		}
		dest = ws_test_wget_strcpy(dest, cur->value, param);
		if (dest == NULL) {
			return WGET_MSG_CONSTRUCT_ERR;
		}
		dest = ws_test_wget_strcpy(dest, g_httpcrnl, param);
		if (dest == NULL) {
			return WGET_MSG_CONSTRUCT_ERR;
		}
		cur = cur->next;
	}
	dest = ws_test_wget_strcpy(dest, g_httpcrnl, param);
	if (dest == NULL) {
		return WGET_MSG_CONSTRUCT_ERR;
	}

	/* entity is needed POST or PUT method */

	if (param->method == WGET_MODE_POST || param->method == WGET_MODE_PUT) {

		/* content length */

		if (!param->encoding) {
			dest = ws_test_wget_strcpy(dest, (char *)param->entity, param);
			if (dest == NULL) {
				return WGET_MSG_CONSTRUCT_ERR;
			}
		}

		/* chunked param->encoding */

		else {
			post_len = strlen(param->entity);
			if (post_len > param->buflen) {
				dest = ws_test_wget_chunksize(dest, param->buflen, param);
				if (dest == NULL) {
					return WGET_MSG_CONSTRUCT_ERR;
				}
				dest = ws_test_wget_strcpy(dest, g_httpcrnl, param);
				if (dest == NULL) {
					return WGET_MSG_CONSTRUCT_ERR;
				}
				dest = ws_test_wget_strlencpy(dest, (char *)param->entity, param->buflen, param);
				if (dest == NULL) {
					return WGET_MSG_CONSTRUCT_ERR;
				}
				dest = ws_test_wget_strcpy(dest, g_httpcrnl, param);
				if (dest == NULL) {
					return WGET_MSG_CONSTRUCT_ERR;
				}
			} else {
				dest = ws_test_wget_chunksize(dest, post_len, param);
				if (dest == NULL) {
					return WGET_MSG_CONSTRUCT_ERR;
				}
				dest = ws_test_wget_strcpy(dest, g_httpcrnl, param);
				if (dest == NULL) {
					return WGET_MSG_CONSTRUCT_ERR;
				}
				dest = ws_test_wget_strcpy(dest, (char *)param->entity, param);
				if (dest == NULL) {
					return WGET_MSG_CONSTRUCT_ERR;
				}
				dest = ws_test_wget_strcpy(dest, g_httpcrnl, param);
				if (dest == NULL) {
					return WGET_MSG_CONSTRUCT_ERR;
				}
				dest = ws_test_wget_strlencpy(dest, "0", 1, param);
				if (dest == NULL) {
					return WGET_MSG_CONSTRUCT_ERR;
				}
				dest = ws_test_wget_strcpy(dest, g_httpcrnl, param);
				if (dest == NULL) {
					return WGET_MSG_CONSTRUCT_ERR;
				}
			}
		}
	}
	return dest - param->buffer;
}

static int ws_test_wget_socket_connect(struct ws_test_wget_s *ws)
{
	int sockfd, ret;
	struct timeval tv;
	struct sockaddr_in server;

	/* Create a socket */
	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sockfd < 0) {
		return WGET_SOCKET_CONNECT_ERR;
	}

	/* Set send and receive timeout values */
	tv.tv_sec = WEBCLIENT_CONF_TIMEOUT_MSEC / 1000;
	tv.tv_usec = (WEBCLIENT_CONF_TIMEOUT_MSEC % 1000) * 1000;
	prnt("webclient recv timeout(%d.%d)sec", tv.tv_sec, tv.tv_usec);
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
				   (struct timeval *)&tv, sizeof(struct timeval)) < 0) {
		prnt("ERROR: setsockopt failed");
	}

	/* Get the server address from the host name */
	server.sin_family = AF_INET;
	server.sin_port = htons(ws->port);
	ret = ws_test_wget_gethostip(ws->hostname, &server.sin_addr.s_addr);
	if (ret < 0) {
		/* Could not resolve host (or malformed IP address) */
		prnt("ERROR: Failed to resolve hostname");
		close(sockfd);
		return WGET_SOCKET_CONNECT_ERR;
	}

	/* Connect to server.  First we have to set some fields in the
	 * 'server' address structure.  The system will assign me an arbitrary
	 * local port that is not in use.
	 */
	ret = connect(sockfd, (struct sockaddr *)&server, sizeof(struct sockaddr_in));
	if (ret < 0) {
		prnt("ERROR: connect failed: %d errno: %d", ret, errno);
		close(sockfd);
		return WGET_SOCKET_CONNECT_ERR;
	}
	return sockfd;
}




#ifdef CONFIG_NET_SECURITY_TLS
static int ws_test_wget_base(void *arg)
{
	int sockfd = -1;
	int ret;
	int buf_len, sndlen, len;
	int encoding = CONTENT_LENGTH;
	int state = HTTP_REQUEST_HEADER;
	struct http_message_len_t mlen = {0,};
	struct ws_test_wget_s ws;
	struct http_client_request_t *param = (struct http_client_request_t *)arg;
	struct http_client_response_t response = {0, };
	int read_finish = false;

	//TODO free client_tls
	struct http_client_tls_t *client_tls = (struct http_client_tls_t *)malloc(sizeof(
			struct http_client_tls_t));
	int handshake_retry = WEBCLIENT_CONF_HANDSHAKE_RETRY;

	if (client_tls == NULL) {
		free(param->buffer);
		return -1;
	}

	/* Initialize the state structure */
	memset(&ws, 0, sizeof(struct ws_test_wget_s));
	ws.buffer = param->buffer;
	ws.buflen = param->buflen;

	/* Parse the hostname (with optional port number) and filename from the URL */
	ret = netlib_parsehttpurl(param->url, &ws.port, ws.hostname, CONFIG_WEBCLIENT_MAXHOSTNAME, ws.filename, CONFIG_WEBCLIENT_MAXFILENAME);
	if (ret != 0) {
		prnt("ERROR: Malformed HTTP URL: %s", param->url);
		free(param->buffer);
		free(client_tls);
		return WGET_ERR;
	}

	prnt("hostname='%s' filename='%s'", ws.hostname, ws.filename);

	if (param->tls && ws_test_webclient_tls_init(client_tls, &param->ssl_config)) {
		prnt("Fail to client tls init");
		goto errout_before_tlsinit;
	}

	/* Re-initialize portions of the state structure that could have
	 * been left from the previous time through the loop and should not
	 * persist with the new connection.
	 */
	ws.httpstatus = HTTPSTATUS_NONE;
	ws.offset = 0;
	ws.datend = 0;
	ws.ndx = 0;

	if ((sndlen = ws_test_wget_msg_construct(ws.buffer, param, &ws)) <= 0) {
		prnt("ERROR: construction message failed");
		goto errout_before_tlsinit;
	}

retry:
	if ((sockfd = ws_test_wget_socket_connect(&ws)) < 0) {
		prnt("ERROR: socket failed: %d", errno);
		goto errout_before_tlsinit;
	}

	client_tls->client_fd = sockfd;
	if (param->tls && (ret = ws_test_wget_tls_handshake(client_tls, ws.hostname))) {
		if (handshake_retry-- > 0) {
			if (ret == MBEDTLS_ERR_NET_SEND_FAILED ||
					ret == MBEDTLS_ERR_NET_RECV_FAILED ||
					ret == MBEDTLS_ERR_SSL_CONN_EOF) {
				prnt("Handshake again.... ");
				mbedtls_net_free(&(client_tls->tls_client_fd));
				mbedtls_ssl_free(&(client_tls->tls_ssl));
				goto retry;
			}
		}
		goto errout;
	}

	buf_len = 0;
	while (sndlen > 0) {
		if (param->tls) {
			ret = mbedtls_ssl_write(&(client_tls->tls_ssl),
									(const unsigned char *)param->buffer + buf_len,
									sndlen);
		} else {
			ret = send(sockfd, param->buffer + buf_len, sndlen, 0);
		}
		if (ret < 1) {
			prnt("ERROR: send failed: %d", ret);
			goto errout;
		} else {
			sndlen -= ret;
			buf_len += ret;
			prnt("SEND SUCCESS: send %d bytes", ret);
		}
	}

	if (param->callback && param->response == NULL) {
		param->response = &response;
		if (ws_test_http_client_response_init(param->response) < 0) {
			prnt("ERROR: response init failed: %d", ret);
			param->response = NULL;
			goto errout;
		}
	}

	int loopcount = 0;
	while (!read_finish) {
		prnt("Receive start");
		memset(param->response->message, 0, WEBCLIENT_CONF_MAX_MESSAGE_SIZE);
		if (param->tls) {
			len = mbedtls_ssl_read(&(client_tls->tls_ssl),
								   (unsigned char *)param->response->message,
								   WEBCLIENT_CONF_MAX_MESSAGE_SIZE);
		} else {
			len = recv(sockfd, param->response->message,
					   WEBCLIENT_CONF_MAX_MESSAGE_SIZE, 0);
		}

		if (len < 0) {
			prnt("Error: Receive Fail");
			goto errout;
		} else if (len == 0) {
			prnt("Finish read");
			if (mlen.message_len - mlen.sentence_start == mlen.content_len) {
				prnt("download completed successfully");
				break;
			} else {
				prnt("Error: Receive Fail");
				goto errout;
			}
		}

		usleep(1);
		read_finish = http_parse_message(param->response->message,
						 len, NULL, param->response->url,
						 &param->response->entity,
						 &encoding, &state, &mlen,
						 param->response->headers,
						 NULL, param->response, NULL, 0);

		++loopcount;
		prnt("====== loopcount : %d read_finish : %d=====", loopcount, read_finish);
		if (read_finish == HTTP_ERROR) {
			prnt("Error: Parse message Fail");
			goto errout;
		}

		param->response->method = param->method;
		param->response->url = param->url;

		if (param->callback && param->response->entity_len != 0) {
			param->callback(param->response);
		}
	}

	if (param->callback) {
		ws_test_http_client_response_release(param->response);
	}
	
	if (param->tls) {
		ws_test_wget_tls_release(client_tls);
		ws_test_wget_tls_ssl_release(client_tls);
	}
	free(client_tls);
	if (!param->tls) {
		close(sockfd);
	}
	free(param->buffer);
	param->async_flag = WGET_OK;
	return WGET_OK;

errout:
	if (param->callback && param->response) {
		ws_test_http_client_response_release(param->response);
	}
	if (param->tls) {
		ws_test_wget_tls_ssl_release(client_tls);
	}
errout_before_tlsinit:
	if (param->tls) {
		ws_test_wget_tls_release(client_tls);
	}
	if (client_tls) {
		free(client_tls);
	}
	if (!param->tls && sockfd > 0) {
		close(sockfd);
	}
	free(param->buffer);
	param->async_flag = WGET_ERR;
	return WGET_ERR;
}
#endif

int ws_test_client_send_request(struct http_client_request_t *request)
{
	if (request == NULL) {
		prnt("Error: Request is null");
		return -1;
	}
	if (request->method < WGET_MODE_GET || request->method > WGET_MODE_DELETE) {
		prnt("Error: Incorrect method value!!");
		return -1;
	}
	if (request->buffer == NULL) {
		prnt("Error: Buffer is NULL!!");
		return -1;
	}
	if (request->buflen <= 0) {
		prnt("Error: Buffer length must be bigger than 0!!");
		goto errret;
	}
	if (request->encoding != CONTENT_LENGTH && request->encoding != CHUNKED_ENCODING) {
		prnt("Error: Incorrect encoding value!!");
		goto errret;
	}

	// request->callback == 0, sync call
	int ret = ws_test_wget_base((void *)request);
	return ret;
errret:
	free(request->buffer);
	return -1;
}

static int ws_test_http_client_send_request(struct http_client_request_t *request,
		 void *ssl_config, struct http_client_response_t *response, wget_callback_t cb)
{
#ifdef CONFIG_NET_SECURITY_TLS
	struct mallinfo data;
	struct http_client_ssl_config_t *ssl_conf = ssl_config;
#endif

	if (request == NULL) {
		prnt("Error: Request is null");
		return -1;
	}

	request->tls = false;
	request->response = response;
	request->callback = cb;

	if (request->url == NULL) {
		prnt("Error: URL is NULL!!");
		return -1;
	}
	if (WEBCLIENT_CONF_MAX_ENTITY_SIZE < strlen(request->entity)) {
		prnt("WEBCLIENT_CONF_MAX_ENTITY_SIZE < strlen(request->entity)");
		return -1;
	}
#ifdef CONFIG_NET_SECURITY_TLS
	if (ssl_conf) {
		request->tls = true;
		memcpy(&request->ssl_config, ssl_conf, sizeof(struct http_client_ssl_config_t));

		data = mallinfo();
		if (data.fordblks < WEBCLIENT_CONF_MIN_TLS_MEMORY) {
			prnt("Error: Not enough memory!!");
			return -1;
		}
	}
#endif

	//TODO free request->buffer
	request->buffer = (char *)malloc(request->buflen);
	if (request->buffer == NULL) {
		prnt("Error: Fail to allocate buffer");
		return -1;
	}

	return ws_test_client_send_request(request);
}

int ws_test_prepare_request(int argc, char** argv, struct http_client_request_t *request)
{
	char *p, *q;
	g_is_test_entity = 0;
	memset(request, 0, sizeof(struct http_client_request_t));


	if (!strncmp(argv[2], "GET", 4)) {
		request->method = WGET_MODE_GET;
	} else if (!strncmp(argv[2], "PUT", 4)) {
		request->method = WGET_MODE_PUT;
	} else if (!strncmp(argv[2], "POST", 5)) {
		request->method = WGET_MODE_POST;
	} else if (!strncmp(argv[2], "DELETE", 7)) {
		request->method = WGET_MODE_DELETE;
	} else {
		prnt("invalid req_type");
		return -1;
	}

	request->url = argv[3];

#ifdef CONFIG_NET_SECURITY_TLS
	if (!strncmp(request->url, "https", 5)) {
		g_https = 1;
	} else
#endif
	if (!strncmp(request->url, "http", 4)) {
		g_https = 0;
	} else {
		prnt("issue with url");
		return -1;
	}

	for (int i = 4; i < argc; i++) {
		p = argv[i];
		if ((q = strchr(p, '=')) == NULL) {
			prnt("issue in optional args, '=' not found");
			return -1;
		}
		q++; // *q++ = '\0';

		if (strncmp(p, "entity", 6) == 0) {
			request->entity = q;
		} else if (strncmp(p, "chunked", 7) == 0) {
			request->encoding = atoi(q);
		} else if (strncmp(p, "test_entity", 11) == 0) {
			int t = atoi(q);
			if (t > 0 && t <= WEBCLIENT_CONF_MAX_ENTITY_SIZE) {
				request->entity = (char *)malloc(t+1);
				if (request->entity == NULL) {
					prnt("no memory allocated");
					return -1;
				}
				g_is_test_entity = 1;
				memset(request->entity, '1', t);
				request->entity[t] = '\0';
			} else {
				prnt("test_entity is too big");
				return -1;
			}
		} else {
			prnt("issue with optional args");
			return -1;
		}
	}

	request->buflen = WEBSERVER_TEST_BUF_SIZE;
	return 0;
}

int ws_test_process_query(int argc, char** argv)
{
	struct http_client_request_t request;
	struct http_keyvalue_list_t headers;
	struct http_client_response_t response;
	struct http_client_ssl_config_t *ssl_config = NULL;

	int result = ws_test_prepare_request(argc, argv, &request);
	if (result != 0) {
		ws_test_dump_usage();
		if (g_is_test_entity) {
			free(request.entity);
		}
		return result;
	}
	ssl_config = g_https ? &g_ssl_config : NULL;

	// before sending request, initialize keyvalue list for request headers
	http_keyvalue_list_init(&headers);
	http_keyvalue_list_add(&headers, headerfield_connect, headerfield_close); //TODO keep-alive?
	http_keyvalue_list_add(&headers, headerfield_useragent, headerfield_tinyara);
	request.headers = &headers;

	// before sending request by sync function, must initialize response
	if (ws_test_http_client_response_init(&response) < 0) {
		prnt("fail to init response");
		goto release_out;
	}
	if (ws_test_http_client_send_request(&request, ssl_config, &response, NULL)) {
		prnt("fail to send request");
		goto release_out;
	}
	printf("----------sync response----------\n");
	printf("status: %d %s\n", response.status, response.phrase);
	printf("entity_len : %d total len : %d\n", response.entity_len, response.total_len);
	printf("%s\n", response.entity);
	printf("----====----\n");
	printf("%s\n", response.message);
	printf("--------- response ended --------\n");

release_out:
	if (g_is_test_entity) {
		free(request.entity);
	}
	http_keyvalue_list_release(&headers);
	ws_test_http_client_response_release(&response);
	prnt("request ended");

	return 0;
}

// webserver_test iters req_type https://127.0.0.1 chunk trailer keep-alive,
int webserver_test_main(int argc, char *argv[])
{
	int result = -1;
	int iters = 1;

	if (argc < 4) {
		prnt("invalid input");
		ws_test_dump_usage();
		return -1;
	}
	iters = atoi(argv[1]);
	if (iters < 1 || iters > 10000) {
		prnt("iters < 1 || iters > 10000");
		return -1;
	}

	//TODO generate report

	for (int i = 1; i <= iters; i++) {
		result = ws_test_process_query(argc, argv);
		if (result != 0) {
			prnt("ws_test_process_query() failed");
			return result;
		}
		printf("\n------------++++++++++++++++++++++++++++-------------\n\n");
	}

	return 0;
}
