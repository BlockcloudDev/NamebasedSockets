#include <sys/types.h>
#include <netinet/in.h>
#define BIND_8_COMPAT
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include "dns.h"
#include "log.h"
#include "namestacknl.h"

#ifndef NETLINK_NAME_ORIENTED_STACK
#define NETLINK_NAME_ORIENTED_STACK 20
#endif

#define MAX_PAYLOAD 1024  /* maximum payload size*/

/* Definitions thare are ordinarily in <arpa/nameser.h>
 * (or <arpa/nameser8_compat.h, included by <arpa/nameser.h> if BIND_8_COMPAT
 * is defined), but not in android:
 */
#ifndef PACKETSZ
#define PACKETSZ 512
#endif
#ifndef C_IN
#define C_IN 1
#endif
#ifndef T_A
#define T_A 1
#endif
#ifndef T_AAAA
#define T_AAAA 28
#endif

int sock_fd;

#define MAX_NAME_LEN 254

/* Prints the address in rdata to buf, which must be at least 16 bytes in
 * size.
 */
static void print_a(const u_char *ptr, uint16_t rdlength,
 const u_char *start, uint16_t len, char *buf)
{
    if (rdlength != sizeof(uint32_t))
        LOGW("address record has invalid length %d\n", rdlength);
    else if (ptr + rdlength - start > len)
        LOGW("%s", "address record overflows buffer\n");
    else
    {
        char *p = buf;
        uint32_t addr = *(uint32_t *)ptr;
        u_char *addrp;

        for (addrp = (u_char *)&addr;
         addrp - (u_char *)&addr < sizeof(uint32_t);
         addrp++)
        {
            if (addrp == (u_char *)&addr + sizeof(uint32_t) - 1)
                sprintf(p, "%d\n", *addrp);
            else
            {
                int n;

                sprintf(p, "%d.%n", *addrp, &n);
                p += n;
            }
        }
    }
}

#ifndef s6_addr16
#define s6_addr16   __u6_addr.__u6_addr16
#endif

/* Prints the address in rdata to buf, which must be at least 46 bytes in
 * size.
 */
static void print_aaaa(const u_char *ptr, uint16_t rdlength,
 const u_char *start, uint16_t len, char *buf)
{
    if (rdlength != sizeof(struct in6_addr))
        LOGW("address record has invalid length %d\n", rdlength);
    else if (ptr + rdlength - start > len)
        LOGW("%s", "address record overflows buffer\n");
    else
    {
        char *p = buf;
        struct in6_addr *addr = (struct in6_addr *)ptr;
        int i, in_zero = 0;

        for (i = 0; i < 7; i++)
        {
            if (!addr->s6_addr16[i])
            {
                if (i == 0)
                    *p++ = ':';
                if (!in_zero)
                {
                    *p++ = ':';
                    in_zero = 1;
                }
            }
            else
            {
                int n;

                sprintf(p, "%x:%n", ntohs(addr->s6_addr16[i]), &n);
                p += n;
                in_zero = 0;
            }
        }
        sprintf(p, "%x\n", ntohs(addr->s6_addr16[7]));
    }
}

struct query_data
{
	unsigned int seq;
	char name[MAX_NAME_LEN];
};

static void *query_thread(void *arg)
{
	struct query_data *data = arg;
	u_char *buf;
	int len, buflen, msg_len, found_response = 0;
	struct nlmsghdr *nlh = NULL;
	uint16_t rdlength;
	const u_char *rdata;

	LOGI("querying %s (seq %d)\n", data->name, data->seq);

	if (!(buf = malloc(PACKETSZ))) {
		/* OOM */
		return NULL;
	}
	buflen = PACKETSZ;
	len = res_query(data->name, C_IN, T_AAAA, buf, buflen);
	if (len >= 0)
	{
		found_response = !find_answer_of_type(buf, len, T_AAAA, 0,
						      &rdlength, &rdata);
		if (found_response)
		{
			char addrbuf[46];

			print_aaaa(rdata, rdlength, buf, len, addrbuf);
			LOGI("found a valid IPv6 address %s\n", addrbuf);
		}
	}
	if (!found_response)
	{
		len = res_query(data->name, C_IN, T_A, buf, buflen);
		if (len >= 0)
		{
			found_response = !find_answer_of_type(buf, len, T_A, 0,
							      &rdlength,
							      &rdata);
			if (found_response)
			{
				char addrbuf[16];

				print_a(rdata, rdlength, buf, len, addrbuf);
				LOGI("found a valid IPv4 address %s\n",
				     addrbuf);
			}
		}
	}
	if (!found_response)
		LOGW("couldn't resolve %s: %d\n", data->name, h_errno);

	msg_len = sizeof(int);
	if (len > 0)
		msg_len += len;
	nlh = malloc(NLMSG_SPACE(msg_len));
	if (nlh)
	{
		struct sockaddr_nl dest_addr;
		struct iovec iov;
		struct msghdr msg;

		/* Send a reply message */
		memset(&dest_addr, 0, sizeof(dest_addr));
		dest_addr.nl_family = AF_NETLINK;

		nlh->nlmsg_len = NLMSG_SPACE(msg_len);
		nlh->nlmsg_type = NAME_STACK_NAME_REPLY;
		nlh->nlmsg_flags = 0;
		nlh->nlmsg_seq = data->seq;
		nlh->nlmsg_pid = 0;
		memcpy(NLMSG_DATA(nlh), &len, sizeof(len));
		if (len > 0)
			memcpy(NLMSG_DATA(nlh) + sizeof(len), buf, len);

		iov.iov_base = (void *)nlh;
		iov.iov_len = nlh->nlmsg_len;
		msg.msg_name = (void *)&dest_addr;
		msg.msg_namelen = sizeof(dest_addr);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		sendmsg(sock_fd, &msg, 0);

		free(nlh);
	}
	free(data);
	free(buf);
}

static void do_query(unsigned int seq, const char *data, size_t len)
{
	size_t measured_len;

	LOGI("got a query request with seq %d for %s (%d)\n", seq, data, len);
	/* Sanity-check the name */
	if (len <= MAX_NAME_LEN)
	{
		for (measured_len = 0; data[measured_len] && measured_len < len;
		     measured_len++)
			;
		if (!data[measured_len])
		{
			struct query_data *qdata =
				malloc(sizeof(struct query_data));

			if (qdata)
			{
				pthread_t thread_id;

				qdata->seq = seq;
				memcpy(qdata->name, data, measured_len + 1);
				if (pthread_create(&thread_id, NULL,
				    query_thread, qdata))
				{
					LOGW("%s",
                                             "thread creation failed, can't resolve name\n");
					free(qdata);
				}
			}
			else
				LOGW("%s",
                                     "alloc failed, can't resolve name\n");
		}
		else
			LOGW("%s",
                             "query has unterminated name\n");
	}
	else
		LOGW("%s",
                     "query has invalid name length %d\n", len);
}

static void send_qualify_response(unsigned int seq, const char *registered_name)
{
	int msg_len, name_len;
	struct nlmsghdr *nlh = NULL;

	LOGI("qualified as %s\n", registered_name);
	name_len = strlen(registered_name);
	msg_len = sizeof(int) + name_len;
	nlh = malloc(NLMSG_SPACE(msg_len));
	if (nlh)
	{
		struct sockaddr_nl dest_addr;
		struct iovec iov;
		struct msghdr msg;
		int err;

		/* Send a reply message */
		memset(&dest_addr, 0, sizeof(dest_addr));
		dest_addr.nl_family = AF_NETLINK;

		nlh->nlmsg_len = NLMSG_SPACE(msg_len);
		nlh->nlmsg_type = NAME_STACK_QUALIFY_REPLY;
		nlh->nlmsg_flags = 0;
		nlh->nlmsg_seq = seq;
		nlh->nlmsg_pid = 0;
		memcpy(NLMSG_DATA(nlh), &name_len, sizeof(name_len));
		memcpy(NLMSG_DATA(nlh) + sizeof(int), registered_name,
		       name_len);

		iov.iov_base = (void *)nlh;
		iov.iov_len = nlh->nlmsg_len;
		msg.msg_name = (void *)&dest_addr;
		msg.msg_namelen = sizeof(dest_addr);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		err = sendmsg(sock_fd, &msg, 0);
		LOGW("sendmsg returned %d\n", err);

		free(nlh);
	}
}

static const char *get_current_domain(void)
{
#ifndef ANDROID
	return _res.defdname;
#else
	LOGW("%s", "getting current domain unimplemented!\n");
	return NULL;
#endif
}

static void do_qualify(unsigned int seq, const char *data, size_t len)
{
	size_t measured_len;

	LOGI("qualifying %s\n", data);
	/* Sanity-check the name */
	if (len < MAX_NAME_LEN)
	{
		for (measured_len = 0; data[measured_len] && measured_len < len;
		     measured_len++)
			;
		if (!data[measured_len])
		{
			char name[MAX_NAME_LEN];

			memcpy(name, data, measured_len + 1);
			if (name[len - 1] == '.')
			{
				/* name is already fully qualified, just call
				 * back with the same name.
				 */
				send_qualify_response(seq, name);
			}
			else
			{
				const char *domain = get_current_domain();

				if (!domain)
					LOGE("%s",
					     "no current domain, unable to qualify\n");
				else if (strlen(name) + strlen(domain) + 1 <
				    MAX_NAME_LEN)
				{
					char full_name[MAX_NAME_LEN];

					sprintf(full_name, "%s.%s.", name,
						domain);
					send_qualify_response(seq, full_name);
				}
				else
					LOGW("%s", "name too long\n");
			}
		}
		else
			LOGW("%s", "query has unterminated name\n");
	}
	else
		LOGW("query has invalid name length %d\n", len);
}

struct register_data
{
	unsigned int seq;
	char name[MAX_NAME_LEN];
	int num_v6_addresses;
	struct in6_addr *v6_addresses;
	int num_v4_addresses;
	struct in_addr *v4_addresses;
};

static void *register_thread(void *arg)
{
	struct register_data *data = arg;
	int len, msg_len, name_len, err, i;
	struct nlmsghdr *nlh = NULL;
	char registered_name[MAX_NAME_LEN];

	LOGI("registering %s (seq %d)\n", data->name, data->seq);
	LOGI("%d IPv6 addresses:\n", data->num_v6_addresses);
	for (i = 0; i < data->num_v6_addresses; i++)
	{
		char addrbuf[46];

		print_aaaa((const u_char *)&data->v6_addresses[i],
			   sizeof(data->v6_addresses[i]),
			   (const u_char *)data->v6_addresses,
			   data->num_v6_addresses * sizeof(data->v6_addresses[i]),
			   addrbuf);
		LOGI("%s\n", addrbuf);
	}
	LOGI("%d IPv4 addresses:\n", data->num_v4_addresses);
	for (i = 0; i < data->num_v4_addresses; i++)
	{
		char addrbuf[16];

		print_a((const u_char *)&data->v4_addresses[i],
			sizeof(data->v4_addresses[i]),
			(const u_char *)data->v4_addresses,
			data->num_v4_addresses * sizeof(data->v4_addresses[i]),
			addrbuf);
		LOGI("%s\n", addrbuf);
	}
	res_init();
	len = strlen(data->name);
	/* len is guaranteed to be <= MAX_NAME_LEN, see do_register */
	if (data->name[len - 1] == '.')
	{
		char host[MAX_NAME_LEN];
		const char *dot;

		/* Fully-qualified domain name, find domain */
		dot = strchr(data->name, '.');
		/* dot is guaranteed not to be NULL */
		memcpy(host, data->name, dot - data->name);
		host[dot - data->name] = 0;
		LOGI("fully-qualified name %s in domain %s\n", host, dot + 1);
		/* FIXME: actually register name, wait for response */
		strcpy(registered_name, data->name);
		err = 0;
	}
	else
	{
		const char *domain = get_current_domain();

		if (!domain)
		{
			LOGE("%s",
			     "no current domain, unable to register\n");
			err = EADDRNOTAVAIL;
		}
		else
		{
			LOGI("unqualified name %s, registering in domain %s\n",
			     data->name, domain);
			if (strlen(data->name) + strlen(domain) + 1 <
			    MAX_NAME_LEN)
			{
				/* FIXME: actually register name, wait for
				 * response
				 */
				sprintf(registered_name, "%s.%s", data->name,
					domain);
				err = 0;
			}
			else
				err = ENAMETOOLONG;
		}
	}

	msg_len = 2 * sizeof(int);
	name_len = strlen(registered_name);
	if (!err)
		msg_len += name_len;
	nlh = malloc(NLMSG_SPACE(msg_len));
	if (nlh)
	{
		struct sockaddr_nl dest_addr;
		struct iovec iov;
		struct msghdr msg;

		/* Send a reply message */
		memset(&dest_addr, 0, sizeof(dest_addr));
		dest_addr.nl_family = AF_NETLINK;

		nlh->nlmsg_len = NLMSG_SPACE(msg_len);
		nlh->nlmsg_type = NAME_STACK_REGISTER_REPLY;
		nlh->nlmsg_flags = 0;
		nlh->nlmsg_seq = data->seq;
		nlh->nlmsg_pid = 0;
		memcpy(NLMSG_DATA(nlh), &err, sizeof(err));
		if (!err)
		{
			memcpy(NLMSG_DATA(nlh) + sizeof(int), &name_len,
			       sizeof(name_len));
			memcpy(NLMSG_DATA(nlh) + 2 * sizeof(int),
			       registered_name, name_len);
		}
		else
		{
			int zero = 0;

			memcpy(NLMSG_DATA(nlh) + sizeof(int), &zero,
			       sizeof(zero));
		}

		iov.iov_base = (void *)nlh;
		iov.iov_len = nlh->nlmsg_len;
		msg.msg_name = (void *)&dest_addr;
		msg.msg_namelen = sizeof(dest_addr);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		sendmsg(sock_fd, &msg, 0);

		free(nlh);
	}
	if (data->v6_addresses)
		free(data->v6_addresses);
	if (data->v4_addresses)
		free(data->v4_addresses);
	free(data);
}

static void do_register(unsigned int seq, const char *data, size_t len)
{
	size_t measured_len;

	LOGI("got a register request with seq %d for %s (%d)\n", seq, data,
	     len);
	/* Sanity-check the name */
	if (len <= MAX_NAME_LEN)
	{
		for (measured_len = 0; data[measured_len] && measured_len < len;
		     measured_len++)
			;
		if (!data[measured_len])
		{
			struct register_data *qdata =
				malloc(sizeof(struct register_data));

			if (qdata)
			{
				pthread_t thread_id;
				const char *ptr;

				qdata->seq = seq;
				memcpy(qdata->name, data, measured_len + 1);
				ptr = data + measured_len + 1;
				memcpy(&qdata->num_v6_addresses, ptr,
				       sizeof(int));
				ptr += sizeof(int);
				if (qdata->num_v6_addresses) {
					qdata->v6_addresses = malloc(
 						qdata->num_v6_addresses *
 						sizeof(struct in6_addr));
 					if (!qdata->v6_addresses) {
 						free(qdata);
 						LOGW("%s",
                                                     "memory allocation failure, can't register name\n");
 						goto nak;
 					}
 					memcpy(qdata->v6_addresses, ptr,
 					       qdata->num_v6_addresses *
 					       sizeof(struct in6_addr));
 					ptr += qdata->num_v6_addresses *
 						sizeof(struct in6_addr);
 				}
 				else
 					qdata->v6_addresses = NULL;
 				memcpy(&qdata->num_v4_addresses, ptr,
 				       sizeof(int));
 				ptr += sizeof(int);
 				if (qdata->num_v4_addresses) {
 					qdata->v4_addresses = malloc(
 						qdata->num_v4_addresses *
 						sizeof(struct in_addr));
 					if (!qdata->v4_addresses) {
 						if (qdata->v6_addresses)
 							free(qdata->v6_addresses);
 						free(qdata);
 						LOGW("%s",
                                                     "memory allocation failure, can't register name\n");
 						goto nak;
 					}
 					memcpy(qdata->v4_addresses, ptr,
 					       qdata->num_v4_addresses *
 						sizeof(struct in_addr));
 				}
 				else
 					qdata->v4_addresses = NULL;
				if (pthread_create(&thread_id, NULL,
				    register_thread, qdata))
				{
					LOGW("%s",
                                             "thread creation failed, can't resolve name\n");
					free(qdata);
					goto nak;
				}
			}
			else
			{
				LOGW("%s",
                                     "alloc failed, can't resolve name\n");
				goto nak;
			}
		}
		else
		{
			LOGW("%s",
                             "query has unterminated name\n");
			goto nak;
		}
	}
	else
	{
		LOGW("query has invalid name length %d\n", len);
		goto nak;
	}
	return;

nak:
	/* FIXME: nak the name register request */
	return;
}

static void *delete_registration_thread(void *arg)
{
	char *name = arg;
	int len;

	LOGI("deleting registration for %s\n", name);
	res_init();
	len = strlen(name);
	/* len is guaranteed to be <= MAX_NAME_LEN, see do_delete_registration
	 */
	if (name[len - 1] == '.')
	{
		char host[MAX_NAME_LEN];
		const char *dot;

		/* Fully-qualified domain name, find domain */
		dot = strchr(name, '.');
		/* dot is guaranteed not to be NULL */
		memcpy(host, name, dot - name);
		host[dot - name] = 0;
		LOGI("fully-qualified name %s in domain %s\n", host, dot + 1);
		/* FIXME: actually delete the name registration */
	}
	else
	{
		const char *domain = get_current_domain();

		if (domain)
		{
			LOGI("unqualified name %s, deleting from domain %s\n",
			     name, domain);
			if (strlen(name) + strlen(domain) + 1 < MAX_NAME_LEN)
			{
				/* FIXME: actually delete the name registration
				 */
			}
		}
	}

	free(name);
}

static void do_delete_registration(unsigned int seq, const char *data,
				   size_t len)
{
	size_t measured_len;

	LOGI("got a register request with seq %d for %s (%d)\n", seq, data,
	     len);
	/* Sanity-check the name */
	if (len <= MAX_NAME_LEN)
	{
		for (measured_len = 0; data[measured_len] && measured_len < len;
		     measured_len++)
			;
		if (!data[measured_len])
		{
			char *name = malloc(measured_len);

			if (name)
			{
				pthread_t thread_id;

				memcpy(name, data, measured_len + 1);
				if (pthread_create(&thread_id, NULL,
				    delete_registration_thread, name))
				{
					LOGW("%s",
                                             "thread creation failed, can't resolve name\n");
					free(name);
				}
			}
			else
				LOGW("%s",
                                     "alloc failed, can't resolve name\n");
		}
		else
			LOGW("%s",
                             "query has unterminated name\n");
	}
	else
		LOGW("%s",
                     "query has invalid name length %d\n", len);
	return;
}

int run_daemon(void)
{
	res_init();
	sock_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_NAME_ORIENTED_STACK);
	if (sock_fd >= 0) {
		struct sockaddr_nl src_addr, dest_addr;
		struct nlmsghdr *nlh = NULL;
		struct iovec iov;
		struct msghdr msg;
		struct pollfd pfd;

		memset(&src_addr, 0, sizeof(src_addr));
		src_addr.nl_family = AF_NETLINK;
		bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));

		memset(&dest_addr, 0, sizeof(dest_addr));
		dest_addr.nl_family = AF_NETLINK;

		nlh = malloc(NLMSG_SPACE(MAX_PAYLOAD));
		/* Send a register message
		 * FIXME: the message is empty, do I really need MAX_PAYLOAD
		 * data bytes?
		 */
		nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
		nlh->nlmsg_type = NAME_STACK_REGISTER;
		nlh->nlmsg_pid = 0;
		nlh->nlmsg_flags = 0;
		*(char *)NLMSG_DATA(nlh) = 0;

		iov.iov_base = (void *)nlh;
		iov.iov_len = nlh->nlmsg_len;
		msg.msg_name = (void *)&dest_addr;
		msg.msg_namelen = sizeof(dest_addr);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		sendmsg(sock_fd, &msg, 0);

		/* Read message from kernel */
		memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
		recvmsg(sock_fd, &msg, 0);
		/* FIXME: check that it's a reply */
		LOGI("%s", "Received registration reply\n");

		memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
		pfd.fd = sock_fd;
		pfd.events = POLLIN;
		while (poll(&pfd, 1, -1)) {
			recvmsg(sock_fd, &msg, 0);
			switch (nlh->nlmsg_type)
			{
			case NAME_STACK_NAME_QUERY:
				do_query(nlh->nlmsg_seq,
					 NLMSG_DATA(nlh),
					 NLMSG_PAYLOAD(nlh, 0));
				break;
			case NAME_STACK_QUALIFY_QUERY:
				do_qualify(nlh->nlmsg_seq,
					   NLMSG_DATA(nlh),
					   NLMSG_PAYLOAD(nlh, 0));
				break;
			case NAME_STACK_REGISTER_QUERY:
				do_register(nlh->nlmsg_seq,
					    NLMSG_DATA(nlh),
					    NLMSG_PAYLOAD(nlh, 0));
				break;
			case NAME_STACK_REGISTER_DELETE:
				do_delete_registration(nlh->nlmsg_seq,
						       NLMSG_DATA(nlh),
						       NLMSG_PAYLOAD(nlh, 0));
				break;
			default:
				LOGW("unhandled msg type %d\n",
				     nlh->nlmsg_type);
			}
			memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
		}
		/* Close Netlink Socket */
		close(sock_fd);
	}
        else
		LOGE("socket failed: %s (%d)\n", strerror(errno), errno);
	return 0;
}
