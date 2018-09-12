/* $Id: milter-regex.c,v 1.9 2011/11/21 12:13:33 dhartmei Exp $ */

/*
 * Copyright (c) 2003-2011 Daniel Hartmeier
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

static const char rcsid[] = "$Id: milter-regex.c,v 1.9 2011/11/21 12:13:33 dhartmei Exp $";

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#ifdef __linux__
#include <grp.h>
#endif
#include <libmilter/mfapi.h>

#include "milter-regex.h"

extern void	 die(const char *);

static const char	*rule_file_name = "/etc/milter-regex.conf";
static int		 debug = 0;
static pthread_mutex_t	 mutex;

#ifdef GEOIP2
const char *geoip2_db_path = 0;
#endif

static sfsistat		 setreply(SMFICTX *, struct context *,
			    const struct action *);
static struct ruleset	*get_ruleset(void);
static sfsistat		 cb_connect(SMFICTX *, char *, _SOCK_ADDR *);
static sfsistat		 cb_helo(SMFICTX *, char *);
static sfsistat		 cb_envfrom(SMFICTX *, char **);
static sfsistat		 cb_envrcpt(SMFICTX *, char **);
static sfsistat		 cb_header(SMFICTX *, char *, char *);
static sfsistat		 cb_eoh(SMFICTX *);
static sfsistat		 cb_body(SMFICTX *, u_char *, size_t);
static sfsistat		 cb_eom(SMFICTX *);
static sfsistat		 cb_close(SMFICTX *);
static void		 usage(const char *);
static void		 msg(int, struct context *, const char *, ...);

#define USER		"_milter-regex"
#define OCONN		"unix:/var/spool/milter-regex/sock"
#define RCODE_REJECT	"554"
#define RCODE_TEMPFAIL	"451"
#define XCODE_REJECT	"5.7.1"
#define XCODE_TEMPFAIL	"4.7.1"
#define	MAXRS		16

/* Define what sendmail macros should be queried in what context (phase)
 * with smfi_getsymval(). Whether sendmail actually provides specific
 * values depends on configuration of confMILTER_MACROS_*
 */
struct {
	const char *phase;
	const char *name;
} macro[] = {
	{ "connect", "{daemon_name}" },
	{ "connect", "{if_name}" },
	{ "connect", "{if_addr}" },
	{ "connect", "j" },
	{ "connect", "_" },
	{ "helo", "{tls_version}" },
	{ "helo", "{cipher}" },
	{ "helo", "{cipher_bits}" },
	{ "helo", "{cert_subject}" },
	{ "helo", "{cert_issuer}" },
	{ "envfrom", "i" },
	{ "envfrom", "{auth_type}" },
	{ "envfrom", "{auth_authen}" },
	{ "envfrom", "{auth_ssf}" },
	{ "envfrom", "{auth_author}" },
	{ "envfrom", "{mail_mailer}" },
	{ "envfrom", "{mail_host}" },
	{ "envfrom", "{mail_addr}" },
	{ "envrcpt", "{rcpt_mailer}" },
	{ "envrcpt", "{rcpt_host}" },
	{ "envrcpt", "{rcpt_addr}" },
	{ NULL, NULL }
};

#if __linux__ || __sun__
#define	ST_MTIME st_mtime
#else
#define	ST_MTIME st_mtimespec
#endif

static void
mutex_lock(void)
{
	if (pthread_mutex_lock(&mutex))
		die("pthread_mutex_lock");
}

static void
mutex_unlock(void)
{
	if (pthread_mutex_unlock(&mutex))
		die("pthread_mutex_unlock");
}

#ifdef __sun__
int
daemon(int nochdir, int noclose)
{
	pid_t pid;
	int fd;

	if ((pid = fork()) < 0) {
		perror("fork");
		return (1);
	} else if (pid > 0)
		_exit(0);
	if ((pid = setsid()) == -1) {
		perror("setsid");
		return (1);
	}
	if ((pid = fork()) < 0) {
		perror("fork");
		return (1);
	} else if (pid > 0)
		_exit(0);
	if (!nochdir && chdir("/")) {
		perror("chdir");
		return (1);
	}
	if (!noclose) {
		dup2(fd, fileno(stdout));
		dup2(fd, fileno(stderr));
		dup2(open("/dev/null", O_RDONLY, 0), fileno(stdin));
	}
	return (0);
}
#endif


#ifdef GEOIP2

#ifdef GEOIP2_TEST
static void print_geoip2_leaf(struct context *context, const char * const *nodepath) {
	struct MMDB_entry_data_list_s *leaf, *leaf_i;
	if (geoip2_pick_leaf(context->geoip2_result, nodepath, &leaf) == 0) {
		char leafbuf[256];
		const char *s;
		int s_len;
		for (leaf_i = leaf;
		     geoip2_iterate_leaf(&leaf_i, leafbuf, sizeof leafbuf, &s, &s_len) == 0;
		     ) {
			fprintf(stderr,"%s -> %.*s\n",context->host_addr,s_len,s);
		}
		if (geoip2_free_leaf(leaf) < 0)
			perror("geoip2_free_leaf");
	}
}
#endif

static int
prime_geoip2(struct context *context)
{

	if (geoip2_db_path) {
		if ((! context->geoip2_result) && (! context->geoip2_lookup_ret)) {
			if ((context->geoip2_lookup_ret = geoip2_lookup(geoip2_db_path, context->host_addr, &context->geoip2_result)) < 0) {
//				msg(LOG_DEBUG, context, "geoip2_lookup(%s): %s", context->host_addr, strerror(errno));
				return -1;
			}

#ifdef GEOIP2_TEST
			else {
				static const char * const countrypath[] = { "country", "iso_code", (char *)0 };
				print_geoip2_leaf(context, countrypath);
				static const char * const subdivpath[] = { "subdivisions", "0", "iso_code", (char *)0 };
				print_geoip2_leaf(context, subdivpath);
				static const char * const citypath[] = { "city", "names", "en", (char *)0 };
				print_geoip2_leaf(context, citypath);
				static const char * const latpath[] = { "location", "latitude", (char *)0 };
				print_geoip2_leaf(context, latpath);
				static const char * const longpath[] = { "location", "longitude", (char *)0 };
				print_geoip2_leaf(context, longpath);
			}
#endif /* GEOIP2_TEST */
		}
	}

	return 0;
}

static int __attribute__((format(printf,3,4))) snprintf_incremental(char **out, size_t *out_spc, const char *fmt, ...) {
	if (! *out_spc) {
		errno = ENOBUFS;
		return -1;
	}
	va_list ap;
	va_start(ap,fmt);
	int n = vsnprintf(*out, *out_spc, fmt, ap);
	if (n<0) {
		**out = 0;
		return -1;
	}
	if ((size_t)n >= *out_spc) {
		**out = 0;
		errno = ENOBUFS;
		return -1;
	}
	*out_spc -= (size_t)n;
	*out += n;
	return n;
}

static int copy_geoip2_leaf(struct context *context, const char * const *nodepath, char **out, size_t *out_spc) {
	struct MMDB_entry_data_list_s *leaf, *leaf_i;
	if (geoip2_pick_leaf(context->geoip2_result, nodepath, &leaf) == 0) {
		int ret = 0;
		char leafbuf[256];
		const char *s;
		int s_len;
		for (leaf_i = leaf;
		     geoip2_iterate_leaf(&leaf_i, leafbuf, sizeof leafbuf, &s, &s_len) == 0;
		     ) {
			if (snprintf_incremental(out,out_spc,"%.*s%s", s_len, s, leaf_i ? "," : "") < 0) {
				ret = -1;
				break;
			}
		}
		if (geoip2_free_leaf(leaf) < 0)
			perror("geoip2_free_leaf");
		return ret;
	} else {
		if (snprintf_incremental(out,out_spc,"-") < 0)
			return -1;
		else
			return 0;
	}
}

static int geoip2_build_summary(struct context *context) {
	if (! context->geoip2_result) {
		errno = ENOENT;
		return -1;
	}
	size_t spc = 256;
	if (! (context->geoip2_result_summary = malloc(spc)))
		return -1;
	char *cp = context->geoip2_result_summary;

	static const char * const continentpath[] = { "continent", "code", (char *)0 };
	static const char * const countrypath[] = { "country", "iso_code", (char *)0 };
	static const char * const subdivpath[] = { "subdivisions", "0", "iso_code", (char *)0 };
	static const char * const citypath[] = { "city", "names", "en", (char *)0 };
	static const char * const latipath[] = { "location", "latitude", (char *)0 };
	static const char * const longipath[] = { "location", "longitude", (char *)0 };

	if ((snprintf_incremental(&cp,&spc,"%s /",context->host_addr) < 0) ||
	    (copy_geoip2_leaf(context, continentpath, &cp, &spc) < 0) ||
	    (snprintf_incremental(&cp,&spc,"/") < 0) ||
	    (copy_geoip2_leaf(context, countrypath, &cp, &spc) < 0) ||
	    (snprintf_incremental(&cp,&spc,"/") < 0) ||
	    (copy_geoip2_leaf(context, subdivpath, &cp, &spc) < 0) ||
	    (snprintf_incremental(&cp,&spc,"/") < 0) ||
	    (copy_geoip2_leaf(context, citypath, &cp, &spc) < 0) ||
	    (snprintf_incremental(&cp,&spc,"/ ") < 0) ||
	    (copy_geoip2_leaf(context, latipath, &cp, &spc) < 0) ||
	    (snprintf_incremental(&cp,&spc,"/") < 0) ||
	    (copy_geoip2_leaf(context, longipath, &cp, &spc) < 0))
		return -1;

	return 0;
}

#endif /* GEOIP2 */

static sfsistat
setreply(SMFICTX *ctx, struct context *context, const struct action *action)
{
	int result = SMFIS_CONTINUE;

#ifdef GEOIP2
	if (action->type != ACTION_ACCEPT)
		prime_geoip2(context);
	if (context->geoip2_result && (! context->geoip2_result_summary))
		(void)geoip2_build_summary(context);
#endif

	switch (action->type) {
	case ACTION_REJECT:
		msg(LOG_NOTICE, context, "REJECT: %s, HELO: %s, FROM: %s, "
		    "RCPT: %s, From: %s, To: %s, Subject: %s"
#ifdef GEOIP2
		    ", GeoIP2: %s"
#endif
		    , action->msg,
		    context->helo, context->env_from, context->env_rcpt,
		    context->hdr_from, context->hdr_to, context->hdr_subject
#ifdef GEOIP2
		    , context->geoip2_result_summary ? context->geoip2_result_summary : ""
#endif
		    );
		result = SMFIS_REJECT;
		break;
	case ACTION_TEMPFAIL:
		msg(LOG_NOTICE, context, "TEMPFAIL: %s, HELO: %s, FROM: %s, "
		    "RCPT: %s, From: %s, To: %s, Subject: %s"
#ifdef GEOIP2
		    ", GeoIP2: %s"
#endif
		    , action->msg,
		    context->helo, context->env_from, context->env_rcpt,
		    context->hdr_from, context->hdr_to, context->hdr_subject
#ifdef GEOIP2
		    , context->geoip2_result_summary ? context->geoip2_result_summary : ""
#endif
		    );
		result = SMFIS_TEMPFAIL;
		break;
	case ACTION_QUARANTINE:
		if (context->quarantine != NULL)
			free(context->quarantine);
		context->quarantine = strdup(action->msg);
		break;
	case ACTION_DISCARD:
		msg(LOG_NOTICE, context, "DISCARD, HELO: %s, FROM: %s, "
		    "RCPT: %s, From: %s, To: %s, Subject: %s"
#ifdef GEOIP2
		    ", GeoIP2: %s"
#endif
		    ,
		    context->helo, context->env_from, context->env_rcpt,
		    context->hdr_from, context->hdr_to, context->hdr_subject
#ifdef GEOIP2
		    , context->geoip2_result_summary ? context->geoip2_result_summary : ""
#endif
		    );
		result = SMFIS_DISCARD;
		break;
	case ACTION_ACCEPT:
		msg(LOG_DEBUG, context, "ACCEPT, HELO: %s, FROM: %s, "
		    "RCPT: %s, From: %s, To: %s, Subject: %s"
#ifdef GEOIP2
		    ", GeoIP2: %s"
#endif
		    ,
		    context->helo, context->env_from, context->env_rcpt,
		    context->hdr_from, context->hdr_to, context->hdr_subject
#ifdef GEOIP2
		    , context->geoip2_result_summary ? context->geoip2_result_summary : ""
#endif
		    );
#ifdef GEOIP2
		context->cached_SMFIS_ACCEPT = 1;
#else
		result = SMFIS_ACCEPT;
#endif
		break;
	}
	if (action->type == ACTION_REJECT &&
	    smfi_setreply(ctx, (char *)RCODE_REJECT, (char *)XCODE_REJECT,
	    (char *)action->msg) != MI_SUCCESS)
		msg(LOG_ERR, context, "smfi_setreply");
	if (action->type == ACTION_TEMPFAIL &&
	    smfi_setreply(ctx, (char *)RCODE_TEMPFAIL, (char *)XCODE_TEMPFAIL,
	    (char *)action->msg) != MI_SUCCESS)
		msg(LOG_ERR, context, "smfi_setreply");
	return (result);
}

static struct ruleset *
get_ruleset(void)
{
	static struct ruleset *rs[MAXRS] = {};
	static int cur = 0;
	static time_t last_check = 0;
	static struct stat sbo;
	time_t t = time(NULL);
	int load = 0;

	mutex_lock();
	if (!last_check)
		memset(&sbo, 0, sizeof(sbo));
	if (t - last_check >= 10) {
		struct stat sb;

		last_check = t;
		memset(&sb, 0, sizeof(sb));
		if (stat(rule_file_name, &sb))
			msg(LOG_ERR, NULL, "get_ruleset: stat: %s: %s",
			    rule_file_name, strerror(errno));
		else if (memcmp(&sb.ST_MTIME, &sbo.ST_MTIME,
		    sizeof(sb.ST_MTIME))) {
			memcpy(&sbo.ST_MTIME, &sb.ST_MTIME,
			    sizeof(sb.ST_MTIME));
			load = 1;
		}
	}
	if (load || rs[cur] == NULL) {
		int i;
		char err[8192];

		msg(LOG_DEBUG, NULL, "loading new configuration file");
		for (i = 0; i < MAXRS; ++i)
			if (rs[i] != NULL && rs[i]->refcnt == 0) {
				msg(LOG_DEBUG, NULL, "freeing unused ruleset "
				    "%d/%d", i, MAXRS);
				free_ruleset(rs[i]);
				rs[i] = NULL;
			}
		for (i = 0; i < MAXRS; ++i)
			if (rs[i] == NULL)
				break;
		if (i == MAXRS)
			msg(LOG_ERR, NULL, "all rulesets are in use, cannot "
			    "load new one", MAXRS);
		else if (parse_ruleset(rule_file_name, &rs[i], err,
		    sizeof(err)) || rs[i] == NULL)
			msg(LOG_ERR, NULL, "parse_ruleset: %s", err);
		else {
			msg(LOG_INFO, NULL, "configuration file %s loaded "
			    "successfully", rule_file_name);
			cur = i;
		}
	}

	mutex_unlock();
	return (rs[cur]);
}

static struct action *
check_macros(SMFICTX *ctx, struct context *context, const char *phase)
{
	struct action *action;
	int i;
	const char *v;

	for (i = 0; macro[i].phase != NULL; ++i) {
		if (strcmp(macro[i].phase, phase))
			continue;
		if ((v = smfi_getsymval(ctx, (char *)macro[i].name)) == NULL)
			v = "";
		msg(LOG_DEBUG, context, "macro %s = %s", macro[i].name, v);
		if ((action = eval_cond(context, COND_MACRO,
		    macro[i].name, v)) != NULL)
			return (action);
	}

	return (NULL);
}

static sfsistat
cb_connect(SMFICTX *ctx, char *name, _SOCK_ADDR *sa)
{
	struct context *context;
	struct action *action;

	context = calloc(1, sizeof(*context));
	if (context == NULL) {
		msg(LOG_ERR, NULL, "cb_connect: calloc: %s", strerror(errno));
		return (SMFIS_ACCEPT);
	}
	context->rs = get_ruleset();
	if (context->rs == NULL) {
		free(context);
		msg(LOG_ERR, NULL, "cb_connect: get_ruleset");
		return (SMFIS_ACCEPT);
	}
	context->res = calloc(context->rs->maxidx, sizeof(*context->res));
	if (context->res == NULL) {
		free(context);
		msg(LOG_ERR, NULL, "cb_connect: calloc: %s", strerror(errno));
		return (SMFIS_ACCEPT);
	}
	if (smfi_setpriv(ctx, context) != MI_SUCCESS) {
		free(context->res);
		free(context);
		msg(LOG_ERR, NULL, "cb_connect: smfi_setpriv");
		return (SMFIS_ACCEPT);
	}
	context->rs->refcnt++;

	strlcpy(context->host_name, name, sizeof(context->host_name));
	strlcpy(context->host_addr, "unknown", sizeof(context->host_addr));
	if (sa) {
		switch (sa->sa_family) {
		case AF_INET: {
			struct sockaddr_in *sin = (struct sockaddr_in *)sa;

			if (inet_ntop(AF_INET, &sin->sin_addr.s_addr,
			    context->host_addr, sizeof(context->host_addr)) ==
			    NULL)
				msg(LOG_ERR, NULL, "cb_connect: inet_ntop: %s",
				    strerror(errno));
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

			if (inet_ntop(AF_INET6, &sin6->sin6_addr,
			    context->host_addr, sizeof(context->host_addr)) ==
			    NULL)
				msg(LOG_ERR, NULL, "cb_connect: inet_ntop: %s",
				    strerror(errno));
			break;
		}
		}
	}
	msg(LOG_DEBUG, context, "cb_connect('%s', '%s')",
	    context->host_name, context->host_addr);
	if ((action = check_macros(ctx, context, "connect")) != NULL) {
		/* can't really do this, delay */
		/*return (setreply(ctx, context, action)); */
	}
	return (SMFIS_CONTINUE);
}

static sfsistat
cb_helo(SMFICTX *ctx, char *arg)
{
	struct context *context;
	const struct action *action;

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		msg(LOG_ERR, NULL, "cb_helo: smfi_getpriv");
		return (SMFIS_ACCEPT);
	}
	strlcpy(context->helo, arg, sizeof(context->helo));
	msg(LOG_DEBUG, context, "cb_helo('%s')", arg);
	/* multiple HELO imply RSET in sendmail */
	/* evaluate connect arguments here, because we can't call */
	/* setreply from cb_connect */
	eval_clear(context->rs, context->res, COND_CONNECT);
	if ((action = eval_cond(context, COND_CONNECT,
	    context->host_name, context->host_addr)) != NULL)
		return (setreply(ctx, context, action));
	if ((action = eval_end(context->rs, context->res, COND_CONNECT,
	    COND_MACRO)) !=
	    NULL)
		return (setreply(ctx, context, action));
	if ((action = check_macros(ctx, context, "helo")) != NULL)
		return (setreply(ctx, context, action));
	eval_clear(context->rs, context->res, COND_HELO);
	if ((action = eval_cond(context, COND_HELO,
	    arg, NULL)) != NULL)
		return (setreply(ctx, context, action));
	if ((action = eval_end(context->rs, context->res, COND_HELO,
	    COND_MACRO)) != NULL)
		return (setreply(ctx, context, action));
#ifdef GEOIP2
	eval_clear(context->rs, context->res, COND_CONNECTGEO);
	if ((action = eval_cond(context, COND_CONNECTGEO,
	    context->host_addr, NULL)) != NULL)
		return (setreply(ctx, context, action));
	if ((action = eval_end(context->rs, context->res, COND_CONNECTGEO,
			       COND_MACRO)) != NULL)
		return (setreply(ctx, context, action));
#endif

	return (SMFIS_CONTINUE);
}

static sfsistat
cb_envfrom(SMFICTX *ctx, char **args)
{
	struct context *context;
	const struct action *action;

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		msg(LOG_ERR, NULL, "cb_envfrom: smfi_getpriv");
		return (SMFIS_ACCEPT);
	}
#ifdef GEOIP2
	if (context->cached_SMFIS_ACCEPT)
		return SMFIS_CONTINUE;
#endif
	/* multiple MAIL FROM indicate separate messages */
	eval_clear(context->rs, context->res, COND_ENVFROM);
	if (*args != NULL) {
		msg(LOG_DEBUG, context, "cb_envfrom('%s')", *args);
		strlcpy(context->env_from, *args, sizeof(context->env_from));
		if ((action = eval_cond(context, COND_ENVFROM,
		    *args, NULL)) != NULL)
			return (setreply(ctx, context, action));
	}
	if ((action = eval_end(context->rs, context->res, COND_ENVFROM,
	    COND_MACRO)) != NULL)
		return (setreply(ctx, context, action));
	if ((action = check_macros(ctx, context, "envfrom")) != NULL)
		return (setreply(ctx, context, action));
	return (SMFIS_CONTINUE);
}

static sfsistat
cb_envrcpt(SMFICTX *ctx, char **args)
{
	struct context *context;
	const struct action *action;

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		msg(LOG_ERR, NULL, "cb_envrcpt: smfi_getpriv");
		return (SMFIS_ACCEPT);
	}
#ifdef GEOIP2
	if (context->cached_SMFIS_ACCEPT)
		return SMFIS_CONTINUE;
#endif
	/* multiple RCPT TO: possible */
	eval_clear(context->rs, context->res, COND_ENVRCPT);
	if (*args != NULL) {
		msg(LOG_DEBUG, context, "cb_envrcpt('%s')", *args);
		if (context->env_rcpt[0])
			strlcat(context->env_rcpt, " ",
			    sizeof(context->env_rcpt));
		strlcat(context->env_rcpt, *args, sizeof(context->env_rcpt));
		if ((action = eval_cond(context, COND_ENVRCPT,
		    *args, NULL)) != NULL)
			return (setreply(ctx, context, action));
	}
	if ((action = eval_end(context->rs, context->res, COND_ENVRCPT,
	    COND_MACRO)) != NULL)
		return (setreply(ctx, context, action));
	if ((action = check_macros(ctx, context, "envrcpt")) != NULL)
		return (setreply(ctx, context, action));
	return (SMFIS_CONTINUE);
}

static sfsistat
cb_header(SMFICTX *ctx, char *name, char *value)
{
	struct context *context;
	const struct action *action;

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		msg(LOG_ERR, context, "cb_header: smfi_getpriv");
		return (SMFIS_ACCEPT);
	}
#ifdef GEOIP2
	if (context->cached_SMFIS_ACCEPT)
		return SMFIS_CONTINUE;
#endif
	msg(LOG_DEBUG, context, "cb_header('%s', '%s')", name, value);
	if ((action = eval_end(context->rs, context->res, COND_MACRO,
	    COND_HEADER)) != NULL)
		return (setreply(ctx, context, action));
	if (!strcasecmp(name, "From"))
		strlcpy(context->hdr_from, value, sizeof(context->hdr_from));
	else if (!strcasecmp(name, "To"))
		strlcpy(context->hdr_to, value, sizeof(context->hdr_to));
	else if (!strcasecmp(name, "Subject"))
		strlcpy(context->hdr_subject, value,
		    sizeof(context->hdr_subject));
	if ((action = eval_cond(context, COND_HEADER,
	    name, value)) != NULL)
		return (setreply(ctx, context, action));
	return (SMFIS_CONTINUE);
}

static sfsistat
cb_eoh(SMFICTX *ctx)
{
	struct context *context;
	const struct action *action;

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		msg(LOG_ERR, NULL, "cb_eoh: smfi_getpriv");
		return (SMFIS_ACCEPT);
	}
#ifdef GEOIP2
	if (context->cached_SMFIS_ACCEPT)
		return SMFIS_CONTINUE;
#endif
	msg(LOG_DEBUG, context, "cb_eoh()");
	memset(context->buf, 0, sizeof(context->buf));
	context->pos = 0;

	if ((action = eval_end(context->rs, context->res, COND_HEADER, COND_BODY)) != NULL)
		return (setreply(ctx, context, action));

	return (SMFIS_CONTINUE);
}

static sfsistat
cb_body(SMFICTX *ctx, u_char *chunk, size_t size)
{
	struct context *context;

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		msg(LOG_ERR, NULL, "cb_body: smfi_getpriv");
		return (SMFIS_ACCEPT);
	}
#ifdef GEOIP2
	if (context->cached_SMFIS_ACCEPT)
		return SMFIS_CONTINUE;
#endif
	for (; size > 0; size--, chunk++) {
		context->buf[context->pos] = *chunk;
		if (context->buf[context->pos] == '\n' ||
		    context->pos == sizeof(context->buf) - 1) {
			const struct action *action;

			if (context->pos > 0 &&
			    context->buf[context->pos - 1] == '\r')
				context->buf[context->pos - 1] = 0;
			else
				context->buf[context->pos] = 0;
			context->pos = 0;
			msg(LOG_DEBUG, context, "cb_body('%s')", context->buf);
			if ((action = eval_cond(context,
			    COND_BODY, context->buf, NULL)) != NULL) {
				sfsistat maybe_end_early = setreply(ctx, context, action);
#ifdef GEOIP2
				if (maybe_end_early == SMFIS_ACCEPT)
					context->cached_SMFIS_ACCEPT = 1;
				else
#endif
					return maybe_end_early;
			}
		} else
			context->pos++;
	}
	return (SMFIS_CONTINUE);
}

static sfsistat
cb_eom(SMFICTX *ctx)
{
	struct context *context;
	const struct action *action;
	int result = SMFIS_ACCEPT;

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		msg(LOG_ERR, NULL, "cb_eom: smfi_getpriv");
		return (SMFIS_ACCEPT);
	}
	msg(LOG_DEBUG, context, "cb_eom()");

#ifdef GEOIP2
	if (context->geoip2_result && (! context->geoip2_result_summary))
		(void)geoip2_build_summary(context);
	if (context->geoip2_result_summary)
		(void)smfi_insheader(ctx, 0, (char *)"X-GeoIP2-Summary", context->geoip2_result_summary);
#endif

	if ((action = eval_end(context->rs, context->res, COND_BODY,
	    COND_MAX)) != NULL)
		result = setreply(ctx, context, action);
	else
		msg(LOG_DEBUG, context, "ACCEPT, HELO: %s, FROM: %s, "
		    "RCPT: %s, From: %s, To: %s, Subject: %s"
#ifdef GEOIP2
		    ", GeoIP2: %s"
#endif
		    , context->helo, context->env_from, context->env_rcpt,
		    context->hdr_from, context->hdr_to, context->hdr_subject
#ifdef GEOIP2
		    , context->geoip2_result_summary ? context->geoip2_result_summary : ""
#endif
		    );

#ifdef GEOIP2
	if (context->cached_SMFIS_ACCEPT)
		result = SMFIS_ACCEPT;
#endif

	if (context->quarantine != NULL) {
		msg(LOG_NOTICE, context, "QUARANTINE: %s, HELO: %s, FROM: %s, "
		    "RCPT: %s, From: %s, To: %s, Subject: %s"
#ifdef GEOIP2
		    ", GeoIP2: %s"
#endif
		    , action->msg,
		    context->helo, context->env_from, context->env_rcpt,
		    context->hdr_from, context->hdr_to, context->hdr_subject
#ifdef GEOIP2
		    , context->geoip2_result_summary ? context->geoip2_result_summary : ""
#endif
		    );
		if (smfi_quarantine(ctx, context->quarantine) != MI_SUCCESS)
			msg(LOG_ERR, context, "cb_eom: smfi_quarantine");
	}
	context->pos = context->hdr_from[0] = context->hdr_to[0] =
	    context->hdr_subject[0] = 0;
	if (context->quarantine != NULL) {
		free(context->quarantine);
		context->quarantine = NULL;
	}

	return (result);
}

static sfsistat
cb_close(SMFICTX *ctx)
{
	struct context *context;

	context = (struct context *)smfi_getpriv(ctx);
	msg(LOG_DEBUG, context, "cb_close()");
	if (context != NULL) {
		smfi_setpriv(ctx, NULL);
		free(context->res);
		if (context->quarantine != NULL)
			free(context->quarantine);
#ifdef GEOIP2
		if (context->geoip2_result) {
			if (geoip2_release(&context->geoip2_result) < 0)
				perror("geoip2_release");
		}
		if (context->geoip2_result_summary)
			free(context->geoip2_result_summary);
#endif
		context->rs->refcnt--;
		free(context);
	}
	return (SMFIS_CONTINUE);
}

struct smfiDesc smfilter = {
	.xxfi_name = (char *)"milter-regex",	/* filter name */
	.xxfi_version = SMFI_VERSION,	/* version code -- do not change */
	.xxfi_flags = SMFIF_QUARANTINE|SMFIF_ADDHDRS, /* flags */
	.xxfi_connect = cb_connect,	/* connection info filter */
	.xxfi_helo = cb_helo,	/* SMTP HELO command filter */
	.xxfi_envfrom = cb_envfrom,	/* envelope sender filter */
	.xxfi_envrcpt = cb_envrcpt,	/* envelope recipient filter */
	.xxfi_header = cb_header,	/* header filter */
	.xxfi_eoh = cb_eoh,		/* end of header */
	.xxfi_body = cb_body,	/* body block */
	.xxfi_eom = cb_eom,		/* end of message */
	.xxfi_abort = NULL,		/* message aborted */
	.xxfi_close = cb_close,	/* connection cleanup */
	.xxfi_unknown = NULL,
	.xxfi_data = NULL,
	.xxfi_negotiate = NULL
};

static void
__attribute__((format(printf,3,4)))
msg(int priority, struct context *context, const char *fmt, ...) 
{
	va_list ap;
	char msgbuf[8192];

	if ((priority == LOG_DEBUG) && (! debug))
	  return;

	va_start(ap, fmt);
	int offset;
	if (context != NULL)
		offset = snprintf(msgbuf, sizeof msgbuf, "%s [%s]: ", context->host_name,
		    context->host_addr);
	else
		offset = 0;
	vsnprintf(msgbuf + offset, sizeof msgbuf - (size_t)offset, fmt, ap);
	if (debug)
		printf("syslog: %s\n", msgbuf);
	else
		syslog(priority, "%s", msgbuf);
	va_end(ap);
}

static void
usage(const char *argv0)
{
	fprintf(stderr, "usage: %s [-d] [-c config] [-u user] [-p pipe]"
#ifdef GEOIP2
		" [-g <path to GeoIP2 db file>]"
#endif
		"\n", argv0);
	exit(1);
}

void
die(const char *reason)
{
	msg(LOG_ERR, NULL, "die: %s", reason);
	smfi_stop();
	sleep(60);
	/* not reached, smfi_stop() kills thread */
	abort();
}

int
main(int argc, char **argv)
{
	int ch;
	const char *oconn = OCONN;
	const char *user = USER;
	const char *jail = NULL;
	sfsistat r = MI_FAILURE;
	const char *ofile = NULL;

	tzset();
	openlog("milter-regex", LOG_PID | LOG_NDELAY, LOG_MAIL);

	while ((ch = getopt(argc, argv,
#ifdef GEOIP2
		"c:dj:p:u:g:"
#else
		"c:dj:p:u:"
#endif
		)) != -1) {
		switch (ch) {
		case 'c':
			rule_file_name = optarg;
			break;
		case 'd':
			debug = 1;
			break;
		case 'j':
			jail = optarg;
			break;
		case 'p':
			oconn = optarg;
			break;
		case 'u':
			user = optarg;
			break;
#ifdef GEOIP2
		case 'g':
			geoip2_db_path = optarg;
			break;
#endif
		default:
			usage(argv[0]);
		}
	}
	if (argc != optind) {
		fprintf(stderr, "unknown command line argument: %s ...",
		    argv[optind]);
		usage(argv[0]);
	}

	if (!strncmp(oconn, "unix:", 5))
		ofile = oconn + 5;
	else if (!strncmp(oconn, "local:", 6))
		ofile = oconn + 6;
	if (ofile != NULL)
		unlink(ofile);

	/* chroot and drop privileges */
	if (jail != NULL && (chroot(jail) || chdir("/"))) {
		perror("chroot");
		return (1);
	}
	if (!getuid()) {
		struct passwd *pw;

		if ((pw = getpwnam(user)) == NULL) {
			fprintf(stderr, "getpwnam: %s: %s\n", user,
			    strerror(errno));
			return (1);
		}
		if (setgroups(1, &pw->pw_gid)) {
			perror("setgroups");
			return (1);
		}
		if (setgid(pw->pw_gid)) {
			perror("setgid");
			return (1);
		}
		if (setuid(pw->pw_uid)) {
			perror("setuid");
			return (1);
		}
	}

#ifdef GEOIP2
	if (geoip2_db_path && geoip2_opendb(geoip2_db_path) < 0)
		exit(1);
#endif

	if (pthread_mutex_init(&mutex, 0)) {
		fprintf(stderr, "pthread_mutex_init\n");
		goto done;
	}

	if (smfi_setconn((char *)oconn) != MI_SUCCESS) {
		fprintf(stderr, "smfi_setconn: %s: failed\n", oconn);
		goto done;
	}

	if (smfi_register(smfilter) != MI_SUCCESS) {
		fprintf(stderr, "smfi_register: failed\n");
		goto done;
	}

	if (eval_init(ACTION_ACCEPT)) {
		fprintf(stderr, "eval_init: failed\n");
		goto done;
	}

	/* daemonize (detach from controlling terminal) */
	if (!debug && daemon(0, 0)) {
		perror("daemon");
		goto done;
	}
	umask(0177);

	msg(LOG_INFO, NULL, "started: %s", rcsid);
	r = smfi_main();
	if (r != MI_SUCCESS)
		msg(LOG_ERR, NULL, "smfi_main: terminating due to error");
	else
		msg(LOG_INFO, NULL, "smfi_main: terminating without error");

#ifdef GEOIP2
	if (geoip2_db_path) {
		if (geoip2_closedb() < 0)
			fprintf(stderr,"geoip2_closedb(%s): %s\n",geoip2_db_path,strerror(errno));
	}
#endif

done:
	return (r);
}
