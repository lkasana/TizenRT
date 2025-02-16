/****************************************************************************
 *
 * Copyright 2016 Samsung Electronics All Rights Reserved.
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
/****************************************************************************
 * examples/webclient/webclient_main.c
 *
 *   Copyright (C) 2009, 2011, 2015 Gregory Nutt. All rights reserved.
 *   Author: Gregory Nutt <gnutt@nuttx.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name Gregory Nutt nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

/**
* @testcase            lwip_http_01 (client)
* @brief               To send HTTP request messages and receive response messages.
*                      supported methods: GET, POST, PUT, DELETE
*                      Entity and encoding are needed only for POST and PUT methods. If an encoding is not for "C", it always uses the content-length.
* @scenario            1. Start webserver at TASH using the command "webserver start". Refer to webserver_main.c to run HTTP server.
*                      2. Start webclient at TASH using the command "webclient GET http://[serverip]/".
* @apicovered
* @precondition                Connect to Wi-Fi. Both ARTIK05x server and ARTIK05x client should be in the same network.
* @postcondition
*/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#include <protocols/webclient.h>

/****************************************************************************
 * Preprocessor Definitions
 ****************************************************************************/

#define WEBCLIENT_STACK_SIZE   (1024 * 8)
#define WEBCLIENT_SCHED_PRI    100
#define WEBCLIENT_SCHED_POLICY SCHED_RR

#define WEBCLIENT_BUF_SIZE     4600
#define WEBCLIENT_FREE_INPUT(node, size) \
	do { \
		int m = 0; \
		for (; m < size; m++) { \
			free(node->argv[m]); \
		} \
		free(node->argv); \
		free(node); \
	} while (0)

/****************************************************************************
 * Private Data
 ****************************************************************************/



struct webclient_input {
	int argc;
	char **argv;
};

const char c_ca_crt_rsa[] =
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

struct http_client_ssl_config_t g_config = {
	(char *)c_ca_crt_rsa, NULL, NULL,
	sizeof(c_ca_crt_rsa), 0, 0, WEBCLIENT_SSL_VERIFY_REQUIRED
};

static int g_running;
static int g_https;
static int g_async;
static int g_testentity;
static int g_total_received_size;
static int g_callback_call_count;

static const char headerfield_connect[] = "Connect";
static const char headerfield_close[] = "close";
static const char headerfield_useragent[] = "User-Agent";
static const char headerfield_tinyara[] = "TinyARA";

/****************************************************************************
 * Private Functions
 ****************************************************************************/
/****************************************************************************
 * Name: callback
 ****************************************************************************/

static void callback(struct http_client_response_t *response)
{
	g_total_received_size += response->entity_len;
	g_callback_call_count++;
	printf("----------async response----------\n");
	printf("status %d %s\n", response->status, response->phrase);
	printf("len : %d Received len : %d total len : %d callback_call count : %d\n", response->entity_len, g_total_received_size, response->total_len, g_callback_call_count);
	printf("%s\n", response->entity);
	printf("---------------------------------\n");
	printf("%s\n", response->message);
	printf("---------------------------------\n");
}

static void dump_webclient_usage(void)
{
	printf("\n  webclient usage:\n");
	printf("   $ webclient <method> <uri> [options...] \n");
	printf("\n");
	printf(" <method>   : %%s (GET, PUT, POST, DELETE)\n");
	printf(" <uri>      : %%s (Host address : should be started with http:// or https://)\n");
	printf("\n [options...] \n");
	printf(" async=1               Enable asynchronous mode (default is synchronous)\n");
	printf(" chunked=1             Enable chunked encoding (default is disabled)\n");
	printf(" entity=DATA           Set entity data (default is NULL)\n");
	printf(" test_entity=SIZE      Test entity size (default is 0)\n");
	printf("\n  example:\n");
	printf("   $ webclient GET https://127.0.0.1/\n");
	printf("   $ webclient GET https://127.0.0.1/ async=1 entity=data\n");
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: wget_main
 ****************************************************************************/

int webclient_init_request(void *arg, struct http_client_request_t *request)
{
	int argc, i;
	char **argv;
	char *p, *q;
	int ret = -1;
	struct webclient_input *input;

	input = arg;
	argc = input->argc;
	argv = input->argv;

	g_async = 1;
	g_testentity = 0;
	memset(request, 0, sizeof(struct http_client_request_t));

	if (argc < 3) {
		goto exit;
	}

	if (!strncmp(argv[1], "GET", 4)) {
		request->method = WGET_MODE_GET;
	} else if (!strncmp(argv[1], "PUT", 4)) {
			request->method = WGET_MODE_PUT;
	} else if (!strncmp(argv[1], "POST", 5)) {
		request->method = WGET_MODE_POST;
	} else if (!strncmp(argv[1], "DELETE", 7)) {
		request->method = WGET_MODE_DELETE;
	} else {
		goto exit;
	}

	/* argument2 is url. */
	request->url = (char *)malloc(strlen(argv[2]) + 1);
	if (!request->url) {
		goto exit;
	}
	strncpy(request->url, argv[2], strlen(argv[2]));
	request->url[strlen(argv[2])] = '\0';

#ifdef CONFIG_NET_SECURITY_TLS
	if (!strncmp(request->url, "https", 5)) {
		g_https = 1;
	} else
#endif
	if (!strncmp(request->url, "http", 4)) {
		g_https = 0;
	} else {
		goto exit;
	}

	for (i = 3; i < argc; i++) {
		p = argv[i];
		if ((q = strchr(p, '=')) == NULL) {
			goto exit;
		}
		*q++ = '\0';

		if (strncmp(p, "async", 5) == 0) {
			g_async = atoi(q);
		} else if (strncmp(p, "entity", 6) == 0) {
				request->entity = q;
		} else if (strncmp(p, "chunked", 7) == 0) {
			request->encoding = atoi(q);
		} else if (strncmp(p, "test_entity", 11) == 0) {
			int t = atoi(q);
			if (t > 0 && t <= WEBCLIENT_CONF_MAX_ENTITY_SIZE) {
				request->entity = (char *)malloc(t);
				if (request->entity == NULL) {
					goto exit;
				}
				g_testentity = 1;
				memset(request->entity, '1', t);
			} else {
				printf("entity is too big\n");
				goto exit;
			}
		} else {
			goto exit;
		}
	}

	request->buflen = WEBCLIENT_BUF_SIZE;
	ret = 0;
exit:
	WEBCLIENT_FREE_INPUT(input, input->argc);

	return ret;
}

pthread_addr_t webclient_cb(void *arg)
{
	struct http_client_request_t request;
	struct http_keyvalue_list_t headers;
	struct http_client_response_t response;
	struct http_client_ssl_config_t *ssl_config = NULL;

	if (webclient_init_request(arg, &request) != 0) {
		dump_webclient_usage();
		if (g_testentity && request.entity) {
			free(request.entity);
		}
		return NULL;
	}

	ssl_config = g_https ? &g_config : NULL;

	/* before sending request,
	 * must initialize keyvalue list for request headers
	 */
	http_keyvalue_list_init(&headers);
	http_keyvalue_list_add(&headers, headerfield_connect, headerfield_close);
	http_keyvalue_list_add(&headers, headerfield_useragent, headerfield_tinyara);
	request.headers = &headers;

	/* before sending request by sync function,
	 * must initialize response structure
	 */
	if (g_async) {
		if (http_client_send_request_async(&request, ssl_config, (wget_callback_t)callback)) {
			printf("fail to send request\n");
			goto release_out;
		}
		/* sleep for end request */
		while (request.async_flag > 0) {
			usleep(100000);
		}
		if (request.async_flag < 0) {
			printf("fail to send request\n");
		}
	} else {
		if (http_client_response_init(&response) < 0) {
			printf("fail to response init\n");
			goto release_out;
		}
		if (http_client_send_request(&request, ssl_config, &response)) {
			printf("fail to send request\n");
			goto release_out;
		}
		printf("----------sync response----------\n");
		printf("status %d %s\n", response.status, response.phrase);
		printf("%s\n", response.entity);
		printf("---------------------------------\n");
	}

release_out:
	if (g_testentity) {
		free(request.entity);
		g_testentity = 0;
	}
	/* after sending request by sync function,
	 * must release response structure
	 */
	if (g_async == 0) {
		http_client_response_release(&response);
	}
	/* before finish of app,
	 * must release keyvalue list for request headers
	 */
	http_keyvalue_list_release(&headers);
	printf("end request\n");

	return NULL;
}

int webclient_main(int argc, char *argv[])
{
	pthread_attr_t attr;
	int status;
	struct sched_param sparam;
	pthread_t tid;
	struct webclient_input *input = NULL;
	g_total_received_size = 0;
	g_callback_call_count = 0;

	if (g_running) {
		printf("Previous request is in process, Please wait.\n");
		return -1;
	} else {
		g_running = 1;
	}

	status = pthread_attr_init(&attr);
	if (status != 0) {
		printf("fail to start webclient\n");
		g_running = 0;
		return -1;
	}

	sparam.sched_priority = WEBCLIENT_SCHED_PRI;
	status = pthread_attr_setschedparam(&attr, &sparam);
	status = pthread_attr_setschedpolicy(&attr, WEBCLIENT_SCHED_POLICY);
	status = pthread_attr_setstacksize(&attr, WEBCLIENT_STACK_SIZE);

	input = (struct webclient_input *)malloc(sizeof(struct webclient_input));
	if (!input) {
		printf(" malloc fail\n");
		return 0;
	}
	input->argv = (char **)malloc(sizeof(char *) * argc);
	if (!input->argv) {
		free(input);
		printf(" malloc argv fail\n");
		return 0;
	}

	input->argc = argc;
	int i = 0;
	for (; i < argc; i++) {
		input->argv[i] = (char *)malloc(sizeof(char) * (strlen(argv[i]) + 1));
		if (!input->argv[i]) {
			WEBCLIENT_FREE_INPUT(input, i);
			return -1;
		}
		strncpy(input->argv[i], argv[i], strlen(argv[i]) + 1);
	}

	status = pthread_create(&tid, &attr, webclient_cb, input);
	if (status < 0) {
		printf("fail to start webclient\n");
		WEBCLIENT_FREE_INPUT(input, argc);

		g_running = 0;
		return -1;
	}
	pthread_setname_np(tid, "webclient");

	pthread_join(tid, NULL);

	g_running = 0;
	return 0;
}
