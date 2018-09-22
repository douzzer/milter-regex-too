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
#define SYSLOG_NAMES
#include <syslog.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/time.h>
#ifdef __linux__
#include <grp.h>
#endif

#include "milter-regex.h"

static const char	*rule_file_name = "/etc/milter-regex.conf";
int		 debug = 0;
static int starting_up = 1;
static pthread_mutex_t	 ruleset_mutex = PTHREAD_MUTEX_INITIALIZER;

#ifdef GEOIP2
const char *geoip2_db_path = 0;
#endif

static sfsistat		 setreply(SMFICTX *, struct context *,
				  int phase, const struct action *);
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
static const struct {
	cond_t phase;
	const char *name;
} macro[] = {
	{ COND_CONNECT, "{daemon_name}" },
	{ COND_CONNECT, "{if_name}" },
	{ COND_CONNECT, "{if_addr}" },
	{ COND_CONNECT, "j" },
	{ COND_CONNECT, "_" },
	{ COND_CONNECT, "{client_resolve}" },
	{ COND_HELO, "{tls_version}" },
	{ COND_HELO, "{cipher}" },
	{ COND_HELO, "{cipher_bits}" },
	{ COND_HELO, "{cert_subject}" },
	{ COND_HELO, "{cert_issuer}" },
	{ COND_HELO, "{verify}" },
	{ COND_HELO, "{server_name}" },
	{ COND_HELO, "{server_addr}" },
	{ COND_ENVFROM, "i" },
	{ COND_ENVFROM, "{auth_type}" },
	{ COND_ENVFROM, "{auth_authen}" },
	{ COND_ENVFROM, "{auth_ssf}" },
	{ COND_ENVFROM, "{auth_authen}" },
	{ COND_ENVFROM, "{mail_mailer}" },
	{ COND_ENVFROM, "{mail_host}" },
	{ COND_ENVFROM, "{mail_addr}" },
	{ COND_ENVRCPT, "{rcpt_mailer}" },
	{ COND_ENVRCPT, "{rcpt_host}" },
	{ COND_ENVRCPT, "{rcpt_addr}" },
	{ COND_NONE, NULL }
};

static const char
	connect_macrolist[] = "{daemon_name},{if_name},{if_addr},j,_,{client_resolve}",
	helo_macrolist[] = "{tls_version},{cipher},{cipher_bits},{cert_subject},{cert_issuer},{verify},{server_name},{server_addr}",
	envfrom_macrolist[] = "i,{auth_type},{auth_authen},{auth_ssf},{auth_authen},{mail_mailer},{mail_host},{mail_addr}",
	envrcpt_macrolist[] = "{rcpt_mailer},{rcpt_host},{rcpt_addr}";

#if __linux__ || __sun__
#define	ST_MTIME st_mtime
#else
#define	ST_MTIME st_mtimespec
#endif

static void
ruleset_mutex_lock(void)
{
	int rv = pthread_mutex_lock(&ruleset_mutex);
	if (rv)
		die_with_errno(rv,"pthread_mutex_lock");
}

static void
ruleset_mutex_unlock(void)
{
	int rv = pthread_mutex_unlock(&ruleset_mutex);
	if (rv)
		die_with_errno(rv,"pthread_mutex_unlock");
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

static int
prime_geoip2(struct context *context)
{
	if (geoip2_db_path) {
		if ((! context->geoip2_result) && (! context->geoip2_lookup_ret)) {
			if ((context->geoip2_lookup_ret = geoip2_lookup(geoip2_db_path, context->host_addr, &context->geoip2_result)) < 0)
				return -1;
		} else if (context->geoip2_lookup_ret < 0) {
			errno = EINVAL;
			return -1;
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

	if ((snprintf_incremental(&cp,&spc,"%s%s%s %s /", context->message_id, context->message_id[0] ? "@" : "",context->my_name,context->host_addr) < 0) ||
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

static void
setreply_lognotice(struct context *context) {
	int lvl;
	if ((! context->action) || (context->action->type == ACTION_ACCEPT) || (context->action->type == ACTION_WHITELIST))
		lvl = LOG_DEBUG;
	else
		lvl = LOG_INFO;

	if ((lvl == LOG_DEBUG) && (! debug))
		return;

	const char *action_name = 0;
	char action_name_upcased[64];
	if (! context->action) {
		switch(context->message_status) {
		case MESSAGE_ABORTED:
			action_name = "ABORTED/NOACTION";
			break;
		case MESSAGE_INPROGRESS:
			action_name = "EARLY/NOACTION";
			break;
		case MESSAGE_COMPLETED:
			action_name = "FALLTHROUGH";
			break;
		}
	} else {
		action_name = lookup_action_name(context->action->type);
		switch(context->message_status) {
		case MESSAGE_ABORTED:
			strcpy(action_name_upcased,"ABORTED/");
			break;
		case MESSAGE_INPROGRESS:
			strcpy(action_name_upcased,"EARLY/");
			break;
		case MESSAGE_COMPLETED:
			action_name_upcased[0] = 0;
			break;
		}
		for (char *cp = action_name_upcased + strlen(action_name_upcased);; ++cp, ++action_name) {
			*cp = toupper(*action_name);
			if (! *action_name)
				break;
		}
		action_name = action_name_upcased;
	}

#ifdef GEOIP2
	if ((! context->action) || (context->action->type != ACTION_WHITELIST))
		prime_geoip2(context);
	if (context->geoip2_result && (! context->geoip2_result_summary))
		(void)geoip2_build_summary(context);
	const char *geoip2_result_summary;
	if (context->geoip2_result_summary) {
		geoip2_result_summary = strchr(context->geoip2_result_summary,'/');
		if (! geoip2_result_summary)
			geoip2_result_summary = context->geoip2_result_summary;
	} else
		geoip2_result_summary = "";
#endif

	const char *last_phase_done = lookup_cond_name(context->last_phase_done);

	if (debug)
		msg(lvl, context, "%s L%d %+lld.%03lld ms (cum_eval %lld.%03lld ms, cum_check %d) @%s: %s%sPTR: %s, TLS: %s, HELO: %s, Authen: %s, FROM: %s, "
		    "RCPT: %s, From: %s, To: %s, Subject: %s"
#ifdef GEOIP2
		    ", GeoIP2: %s"
#endif
		    , action_name,
		    context->action ? context->action->lineno : 0,
		    context->action ? (context->action_at - context->created_at) / 1000LL : 0LL,
		    context->action ? (context->action_at - context->created_at) % 1000LL : 0LL,
		    context->eval_time_cum / 1000LL,
		    context->eval_time_cum % 1000LL,
		    context->check_cond_count,
		    last_phase_done,
		    (context->action && context->action->msg) ? context->action->msg : "",
		    (context->action && context->action->msg && context->action->msg[0]) ? ", " : "",
		    context->client_resolve,
		    context->tls_status,
		    context->helo,
		    context->auth_authen,
		    context->env_from,
		    context->env_rcpt,
		    context->hdr_from,
		    context->hdr_to,
		    context->hdr_subject
#ifdef GEOIP2
		    , geoip2_result_summary
#endif
		    );
	else
		msg(lvl, context, "%s L%d @%s (%d): %s%sPTR: %s, TLS: %s, HELO: %s, Authen: %s, FROM: %s, "
		    "RCPT: %s, From: %s, To: %s, Subject: %s"
#ifdef GEOIP2
		    ", GeoIP2: %s"
#endif
		    , action_name,
		    context->action ? context->action->lineno : 0,
		    last_phase_done,
		    context->check_cond_count,
		    (context->action && context->action->msg) ? context->action->msg : "",
		    (context->action && context->action->msg && context->action->msg[0]) ? ", " : "",
		    context->client_resolve,
		    context->tls_status,
		    context->helo,
		    context->auth_authen,
		    context->env_from,
		    context->env_rcpt,
		    context->hdr_from,
		    context->hdr_to,
		    context->hdr_subject
#ifdef GEOIP2
		    , geoip2_result_summary
#endif
		    );
}

static sfsistat
setreply(SMFICTX *ctx, struct context *context, int phase, const struct action *action)
{
	sfsistat result = SMFIS_CONTINUE;

	context->action = action;
	context->last_phase_done = phase;
	if (debug) {
		struct timeval now;
		(void)gettimeofday(&now,0);
		context->action_at = ((long long int)now.tv_sec * 1000000LL) + (long long int)now.tv_usec;
	}

	switch (action->type) {
	case ACTION_REJECT:
		result = SMFIS_REJECT;
		break;
	case ACTION_TEMPFAIL:
		result = SMFIS_TEMPFAIL;
		break;
	case ACTION_QUARANTINE:
		/* result stays SMFIS_CONTINUE */
		break;
	case ACTION_DISCARD:
		result = SMFIS_DISCARD;
		break;
	case ACTION_WHITELIST:
	case ACTION_ACCEPT:
		result = SMFIS_ACCEPT;
		break;
	case ACTION_NONE:
		;
	}
	if (action->type == ACTION_REJECT &&
	    smfi_setreply(ctx, (char *)RCODE_REJECT, (char *)XCODE_REJECT,
	    (char *)action->msg) != MI_SUCCESS)
		msg(LOG_ERR, context, "smfi_setreply");
	if (action->type == ACTION_TEMPFAIL &&
	    smfi_setreply(ctx, (char *)RCODE_TEMPFAIL, (char *)XCODE_TEMPFAIL,
	    (char *)action->msg) != MI_SUCCESS)
		msg(LOG_ERR, context, "smfi_setreply");

	context->action_result = result;

	if ((phase == COND_CONNECT) || (phase == COND_CONNECTGEO) || (phase == COND_BODY)) {
		if ((result == SMFIS_ACCEPT) || (result == SMFIS_DISCARD)) {
			if ((phase == COND_BODY) && (context->smfi_phases & SMFIP_SKIP))
				return SMFIS_SKIP;
			else
				return SMFIS_CONTINUE;
		} else
			return result;
	} else
		return SMFIS_CONTINUE;
}

static struct stat sbo;

static struct ruleset *
get_ruleset(void)
{
	static struct ruleset *rs[MAXRS] = {};
	static int cur = 0;
	static time_t last_check = 0;
	time_t t = time(NULL);
	int load = 0;

	ruleset_mutex_lock();
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

		int n_old_rs = 0;
		for (i = 0; i < MAXRS; ++i) {
			if (! rs[i])
				continue;
			++n_old_rs;
			if (rs[i]->refcnt == 0) {
				msg(LOG_DEBUG, NULL, "freeing unused ruleset "
				    "%d/%d", i, MAXRS);
				free_ruleset(rs[i]);
				rs[i] = NULL;
			}
		}
		msg(LOG_DEBUG, NULL, "%sloading configuration file %s", n_old_rs ? "re" : "", rule_file_name);
		for (i = 0; i < MAXRS; ++i)
			if (rs[i] == NULL)
				break;
		if (i == MAXRS)
			msg(LOG_ERR, NULL, "all rulesets are in use (max %d), cannot "
			    "load new one", MAXRS);
		else if (parse_ruleset(rule_file_name, &rs[i], err,
		    sizeof(err)) || rs[i] == NULL) {
			msg(LOG_ERR, NULL, "parse_ruleset: %s", err);
			if (rs[i]) {
				free_ruleset(rs[i]);
				rs[i] = 0;
			}
		} else {
			msg(LOG_INFO, NULL, "configuration file %s %sloaded "
			    "successfully, mtime %lld", rule_file_name, n_old_rs ? "re" : "", (long long int)sbo.st_mtime);
			cur = i;
		}
	}

	if (rs[cur])
		++rs[cur]->refcnt;

	ruleset_mutex_unlock();
	return (rs[cur]);
}

static void release_ruleset(struct ruleset *rs) {
	ruleset_mutex_lock();
	if (--rs->refcnt < 0)
		msg(LOG_ERR, 0, "rulset refcount is %d!\n",rs->refcnt);
	ruleset_mutex_unlock();
}

static struct action *
check_macros(SMFICTX *ctx, struct context *context, cond_t phase)
{
	struct action *action;
	int i;
	const char *v;

	for (i = 0; macro[i].phase != COND_NONE; ++i) {
		if (macro[i].phase != phase)
			continue;
		v = smfi_getsymval(ctx, (char *)macro[i].name); /* may be null.  allow testing for that. */
		if (debug)
			msg(LOG_DEBUG, context, "macro %s = %s", macro[i].name, v ? v : "<unset>");
		if ((action = eval_cond(context, COND_MACRO,
		    macro[i].name, v)) != NULL)
			return (action);
	}

	return (NULL);
}

static sfsistat
cb_negotiate(SMFICTX *ctx,
	     __attribute__((unused)) unsigned long actions,
	     unsigned long phases_offered,
	     __attribute__((unused)) unsigned long unused0,
	     __attribute__((unused)) unsigned long unused1,
	     __attribute__((unused)) unsigned long *actions_output,
	     unsigned long *phases_requested,
	     __attribute__((unused)) unsigned long *unused0_output,
	     __attribute__((unused)) unsigned long *unused1_output) {
	struct context *context;
	context = calloc(1, sizeof(*context));
	if (context == NULL) {
		msg(LOG_ERR, NULL, "cb_connect: calloc: %s", strerror(errno));
		return SMFIS_REJECT; /* "milter startup fails and it will not be contacted again (for the current connection)." */
	}
	if (debug) {
		struct timeval now;
		(void)gettimeofday(&now,0);
		context->created_at = ((long long int)now.tv_sec * 1000000LL) + (long long int)now.tv_usec;
	}
	if (smfi_setpriv(ctx, context) != MI_SUCCESS) {
		free(context);
		msg(LOG_ERR, NULL, "cb_negotiate: smfi_setpriv");
		return SMFIS_REJECT;
	}

	if (smfi_setsymlist(ctx, SMFIM_CONNECT, (char *)connect_macrolist) != MI_SUCCESS)
		msg(LOG_ERR,0,"smfi_setsymlist(CONNECT)");
	if (smfi_setsymlist(ctx, SMFIM_HELO, (char *)helo_macrolist) != MI_SUCCESS)
		msg(LOG_ERR,0,"smfi_setsymlist(HELO)");
	if (smfi_setsymlist(ctx, SMFIM_ENVFROM, (char *)envfrom_macrolist) != MI_SUCCESS)
		msg(LOG_ERR,0,"smfi_setsymlist(ENVFROM)");
	if (smfi_setsymlist(ctx, SMFIM_ENVRCPT, (char *)envrcpt_macrolist) != MI_SUCCESS)
		msg(LOG_ERR,0,"smfi_setsymlist(ENVRCPT)");

	if (phases_offered & SMFIP_SKIP)
		*phases_requested |= SMFIP_SKIP;
	if (phases_offered & SMFIP_RCPT_REJ)
		*phases_requested |= SMFIP_RCPT_REJ;

	context->smfi_phases = *phases_requested;

	return SMFIS_CONTINUE;
}

static sfsistat
cb_connect(SMFICTX *ctx, char *name, _SOCK_ADDR *sa)
{
	struct context *context;
	struct action *action;

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		msg(LOG_ERR, NULL, "cb_helo: smfi_getpriv");
		return (SMFIS_ACCEPT);
	}

	{
		const char *j_name = smfi_getsymval(ctx, (char *)"j");
		if (j_name)
			strlcpy(context->my_name, j_name, sizeof(context->my_name));
	}
	{
		const char *client_resolve = smfi_getsymval(ctx, (char *)"{client_resolve}");
		if (client_resolve)
			strlcpy(context->client_resolve, client_resolve, sizeof(context->client_resolve));
	}

	context->rs = get_ruleset();
	if (context->rs == NULL) {
		free(context);
		smfi_setpriv(ctx, NULL);
		msg(LOG_ERR, NULL, "cb_connect: get_ruleset");
		return (SMFIS_ACCEPT);
	}
	context->res = calloc(context->rs->maxidx, sizeof(*context->res));
	if (context->res == NULL) {
		free(context);
		smfi_setpriv(ctx, NULL);
		msg(LOG_ERR, NULL, "cb_connect: calloc: %s", strerror(errno));
		return (SMFIS_ACCEPT);
	}

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
	if ((action = check_macros(ctx, context, COND_CONNECT)) != NULL)
		return setreply(ctx, context, COND_CONNECT, action);
	eval_clear(context, COND_CONNECT);
	if ((action = eval_cond(context, COND_CONNECT,
				context->host_name, context->host_addr)) != NULL)
		return setreply(ctx, context, COND_CONNECT, action);

	if ((action = eval_end(context, COND_CONNECT,
	    COND_MACRO)) !=
	    NULL)
		return setreply(ctx, context, COND_CONNECT, action);

#ifdef GEOIP2
	eval_clear(context, COND_CONNECTGEO);
	if ((action = eval_cond(context, COND_CONNECTGEO,
				context->host_addr, NULL)) != NULL)
		return setreply(ctx, context, COND_CONNECTGEO, action);
	if ((action = eval_end(context, COND_CONNECTGEO,
			       COND_MACRO)) != NULL)
		return setreply(ctx, context, COND_CONNECTGEO, action);
#endif

	context->action_result = SMFIS_CONTINUE;

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

	{
		const char *TLS_verify = smfi_getsymval(ctx, (char *)"{verify}");
		if (TLS_verify) {
			if (! strcmp(TLS_verify,"NO"))
				strlcpy(context->tls_status, "NOCERT", sizeof(context->tls_status));
			else if (! strcmp(TLS_verify,"OK"))
				strlcpy(context->tls_status, "OKCERT", sizeof(context->tls_status));
			else
				strlcpy(context->tls_status, TLS_verify, sizeof(context->tls_status));
		} else
			strlcpy(context->tls_status, "OFF", sizeof(context->tls_status));
	}

	strlcpy(context->helo, arg, sizeof(context->helo));

	if (context->action)
		return SMFIS_CONTINUE;

	msg(LOG_DEBUG, context, "cb_helo('%s')", arg);
	/* multiple HELO imply RSET in sendmail */

	if ((action = check_macros(ctx, context, COND_HELO)) != NULL)
		return (setreply(ctx, context, COND_HELO, action));
	eval_clear(context, COND_HELO);
	if ((action = eval_cond(context, COND_HELO,
	    arg, NULL)) != NULL)
		return (setreply(ctx, context, COND_HELO, action));
	if ((action = eval_end(context, COND_HELO,
	    COND_MACRO)) != NULL)
		return (setreply(ctx, context, COND_HELO, action));

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

	/* first opportunity to read the Message-ID and auth_authen */
	{
		const char *MessageID = smfi_getsymval(ctx, (char *)"i");
		if (MessageID)
			strlcpy(context->message_id, MessageID, sizeof(context->message_id));
		const char *auth_authen = smfi_getsymval(ctx, (char *)"{auth_authen}");
		if (auth_authen)
			strlcpy(context->auth_authen, auth_authen, sizeof(context->auth_authen));
	}

#ifdef GEOIP2
	/* force reformatting of the summary with the queue ID */
	if (context->geoip2_result_summary) {
		free(context->geoip2_result_summary);
		context->geoip2_result_summary = 0;
	}

#endif

	if (*args != NULL)
		strlcpy(context->env_from, *args, sizeof(context->env_from));

	if (context->action)
		return SMFIS_CONTINUE;

	/* multiple MAIL FROM indicate separate messages */
	eval_clear(context, COND_ENVFROM);
	if (*args != NULL) {
		msg(LOG_DEBUG, context, "cb_envfrom('%s')", *args);
		if ((action = eval_cond(context, COND_ENVFROM,
		    *args, NULL)) != NULL)
			return (setreply(ctx, context, COND_ENVFROM, action));
	}
	if ((action = eval_end(context, COND_ENVFROM,
	    COND_MACRO)) != NULL)
		return (setreply(ctx, context, COND_ENVFROM, action));
	if ((action = check_macros(ctx, context, COND_ENVFROM)) != NULL)
		return (setreply(ctx, context, COND_ENVFROM, action));

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

	if (*args != NULL) {
		if (context->env_rcpt[0])
			strlcat(context->env_rcpt, " ",
				sizeof(context->env_rcpt));
		strlcat(context->env_rcpt, *args, sizeof(context->env_rcpt));
	}

	if (context->action)
		return SMFIS_CONTINUE;

	/* multiple RCPT TO: possible */
	eval_clear(context, COND_ENVRCPT);
	if (*args != NULL) {
		msg(LOG_DEBUG, context, "cb_envrcpt('%s')", *args);
		if ((action = eval_cond(context, COND_ENVRCPT,
		    *args, NULL)) != NULL)
			return (setreply(ctx, context, COND_ENVRCPT, action));
	}
	if ((action = eval_end(context, COND_ENVRCPT,
	    COND_MACRO)) != NULL)
		return (setreply(ctx, context, COND_ENVRCPT, action));
	if ((action = check_macros(ctx, context, COND_ENVRCPT)) != NULL)
		return (setreply(ctx, context, COND_ENVRCPT, action));

	return (SMFIS_CONTINUE);
}

static void zap_ctrls(char *s) {
	while (*s) {
		if (iscntrl(*s))
			*s = '^';
		++s;
	}
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

	if (!strcasecmp(name, "From")) {
		strlcpy(context->hdr_from, value, sizeof(context->hdr_from));
		zap_ctrls(context->hdr_from);
	} else if (!strcasecmp(name, "To")) {
		strlcpy(context->hdr_to, value, sizeof(context->hdr_to));
		zap_ctrls(context->hdr_to);
	} else if (!strcasecmp(name, "Subject")) {
		strlcpy(context->hdr_subject, value,
		    sizeof(context->hdr_subject));
		zap_ctrls(context->hdr_subject);
	}

	if (context->action)
		return SMFIS_CONTINUE;

	if (debug)
		msg(LOG_DEBUG, context, "cb_header('%s', '%s')", name, value);
	if ((action = eval_end(context, COND_MACRO,
	    COND_HEADER)) != NULL)
		return (setreply(ctx, context, COND_HEADER, action));
	if ((action = eval_cond(context, COND_HEADER,
	    name, value)) != NULL)
		return (setreply(ctx, context, COND_HEADER, action));
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

	if (context->action)
		return SMFIS_CONTINUE;

	msg(LOG_DEBUG, context, "cb_eoh()");
	memset(context->buf, 0, sizeof(context->buf));
	context->pos = 0;

	if ((action = eval_end(context, COND_HEADER, COND_BODY)) != NULL)
		return (setreply(ctx, context, COND_HEADER, action));

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

	if (context->action) {
		if (context->smfi_phases & SMFIP_SKIP)
			return SMFIS_SKIP;
		else
			return SMFIS_CONTINUE;
	}

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
			if (debug)
				msg(LOG_DEBUG, context, "cb_body('%s')", context->buf);
			if ((action = eval_cond(context,
			    COND_BODY, context->buf, NULL)) != NULL)
				return (setreply(ctx, context, COND_BODY, action));
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

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		msg(LOG_ERR, NULL, "cb_eom: smfi_getpriv");
		return (SMFIS_ACCEPT);
	}
	msg(LOG_DEBUG, context, "cb_eom()");

	context->message_status = MESSAGE_COMPLETED;

	if (! context->action) {
		if ((action = eval_end(context, COND_BODY,
				       COND_MAX)) != NULL)
			(void)setreply(ctx, context, COND_BODY, action);
	}

	sfsistat result;
	if (context->action)
		result = context->action_result;
	else
		result = SMFIS_ACCEPT;

#ifdef GEOIP2
	if (context->geoip2_result && (! context->geoip2_result_summary))
		(void)geoip2_build_summary(context);
	const char *geoip2_result_summary;
	if (context->geoip2_result_summary) {
		if ((! context->action) || (context->action->type != ACTION_WHITELIST))
			(void)smfi_insheader(ctx, 0, (char *)"X-GeoIP2-Summary", context->geoip2_result_summary);
		geoip2_result_summary = strchr(context->geoip2_result_summary,'/');
		if (! geoip2_result_summary)
			geoip2_result_summary = context->geoip2_result_summary;
	} else
		geoip2_result_summary = "";
#endif

	if ((result == SMFIS_ACCEPT) || (result == SMFIS_CONTINUE)) {
		const char *if_addr;
		if (context->auth_authen[0]
		    || smfi_getsymval(ctx, (char *)"{auth_authen}")
		    || (! strcasecmp(context->host_name,context->my_name))
		    || (! (if_addr = smfi_getsymval(ctx, (char *)"{if_addr}")))
		    || (! strcmp(context->host_addr,if_addr)))
			;
		else {
			const char *last_phase_done = context ? lookup_cond_name(context->last_phase_done) : "?";
			char action_msg_buf[128];
			snprintf(action_msg_buf,sizeof action_msg_buf,
				 "%s%s%s %lld %d %s %d",
				 context->message_id,
				 context->message_id[0] ? "@" : "",
				 context->my_name,
				 (long long int)sbo.st_mtime,
				 context->action ? context->action->lineno : 0,
				 last_phase_done,
				 context->check_cond_count);
			(void)smfi_insheader(ctx, 0, (char *)"X-Milter-Regex-Decision-Trace", action_msg_buf);
		}
	}

	if (context->action && (context->action->type == ACTION_QUARANTINE) /* context->quarantine != NULL */ ) {
		if (smfi_quarantine(ctx, context->action->msg /* context->quarantine */) != MI_SUCCESS)
			msg(LOG_ERR, context, "cb_eom: smfi_quarantine");
	}

	return (result);
}

static sfsistat
cb_abort(SMFICTX *ctx) {
	struct context *context;

	context = (struct context *)smfi_getpriv(ctx);
	msg(LOG_DEBUG, context, "cb_abort()");
	if (context != NULL)
		context->message_status = MESSAGE_ABORTED;
	return SMFIS_CONTINUE;
}

static sfsistat
cb_close(SMFICTX *ctx)
{
	struct context *context;

	context = (struct context *)smfi_getpriv(ctx);
	msg(LOG_DEBUG, context, "cb_close()");
	if (context != NULL) {
		setreply_lognotice(context);
		smfi_setpriv(ctx, NULL);
		free(context->res);
#ifdef GEOIP2
		if (context->geoip2_result) {
			if (geoip2_release(&context->geoip2_result) < 0)
				msg(LOG_CRIT,context,"geoip2_release(): %s",strerror(errno));
		}
		if (context->geoip2_result_summary)
			free(context->geoip2_result_summary);
#endif
		release_ruleset(context->rs);
		free(context);
	}
	return (SMFIS_CONTINUE);
}

struct smfiDesc smfilter = {
	.xxfi_name = (char *)"milter-regex",	/* filter name */
	.xxfi_version = SMFI_VERSION,	/* version code -- do not change */
	.xxfi_flags = SMFIF_QUARANTINE|SMFIF_ADDHDRS|SMFIF_SETSYMLIST, /* flags */
	.xxfi_connect = cb_connect,	/* connection info filter */
	.xxfi_helo = cb_helo,	/* SMTP HELO command filter */
	.xxfi_envfrom = cb_envfrom,	/* envelope sender filter */
	.xxfi_envrcpt = cb_envrcpt,	/* envelope recipient filter */
	.xxfi_header = cb_header,	/* header filter */
	.xxfi_eoh = cb_eoh,		/* end of header */
	.xxfi_body = cb_body,	/* body block */
	.xxfi_eom = cb_eom,		/* end of message */
	.xxfi_abort = cb_abort,		/* message aborted */
	.xxfi_close = cb_close,	/* connection cleanup */
	.xxfi_unknown = NULL,
	.xxfi_data = NULL,
	.xxfi_negotiate = cb_negotiate
};

void
__attribute__((format(printf,3,4)))
msg(int priority, struct context *context, const char *fmt, ...) 
{
	if ((priority == LOG_DEBUG) && (! debug))
		return;

	char msgbuf[8192];
	va_list ap;
	va_start(ap, fmt);
	int offset;
	if (context != NULL)
		offset = snprintf(msgbuf, sizeof msgbuf, "%s@%s %s [%s]: ", context->message_id[0] ? context->message_id : "<noQID>", context->my_name, context->host_name,
				  context->host_addr);
	else
		offset = 0;
	vsnprintf(msgbuf + offset, sizeof msgbuf - (size_t)offset, fmt, ap);
	if (debug) {
		struct timeval now;
		(void)gettimeofday(&now,0);
		long long int created_at, usecs_elapsed;
		if (context) {
			created_at = context->created_at;
			usecs_elapsed = (((long long int)now.tv_sec * 1000000LL) + (long long int)now.tv_usec) - context->created_at;
		} else {
			created_at = (((long long int)now.tv_sec * 1000000LL) + (long long int)now.tv_usec);
			usecs_elapsed = 0;
		}
		const char *priorityname;
		for (int i = 0;; ++i) {
			if (! prioritynames[i].c_name) {
				priorityname = "LOG_???";
				break;
			}
			if (prioritynames[i].c_val == priority) {
				priorityname = prioritynames[i].c_name;
				break;
			}
		}
		printf("%s %lld %+lld.%03lld ms: %s\n", priorityname, created_at / 1000000LL, usecs_elapsed/1000LL, usecs_elapsed%1000LL, msgbuf);
	} else if (starting_up && (priority <= LOG_NOTICE))
		fprintf(stderr,"%s\n", msgbuf);
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
__die(const char *fn, int lineno, int this_errno, const char *reason)
{
	if (this_errno > 0)
		msg(LOG_CRIT, NULL, "die %s@%d (%s): %s", fn, lineno, strerror(this_errno), reason);
	else
		msg(LOG_CRIT, NULL, "die %s@%d: %s", fn, lineno, reason);
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
	const char *user = 0 /* USER */;
	const char *jail = NULL;
	sfsistat r = MI_FAILURE;
	const char *ofile = NULL;

	tzset();

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

	if (! debug)
		openlog("milter-regex", LOG_PID | LOG_NDELAY, LOG_MAIL);

	if (!strncmp(oconn, "unix:", 5))
		ofile = oconn + 5;
	else if (!strncmp(oconn, "local:", 6))
		ofile = oconn + 6;
	else if (*oconn == '/')
		ofile = oconn;
	if (ofile != NULL) {
		struct stat st;
		if ((stat(ofile,&st) == 0) && S_ISREG(st.st_mode)) {
			fprintf(stderr,"socket path %s refers to an existing regular file.\n",ofile);
			exit(1);
		}
		unlink(ofile);
	}

	/* chroot and drop privileges */
	if (jail != NULL && (chroot(jail) || chdir("/"))) {
		perror("chroot");
		return (1);
	}
	if (user) {
		struct passwd *pw;

		errno = 0;
		if ((pw = getpwnam(user)) == NULL) {
			fprintf(stderr, "getpwnam(%s): %s\n", user,
				errno ? strerror(errno) : "no such user");
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

	{
	  struct ruleset *rs = get_ruleset();
	  if (! rs)
	    exit(1);
	  release_ruleset(rs);
	}

#ifdef GEOIP2
	if (geoip2_db_path && geoip2_opendb(geoip2_db_path) < 0)
		exit(1);
#endif

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

	starting_up = 0;

#ifdef GEOIP2
	msg(LOG_INFO, NULL, "started: %s, with GeoIP2 extensions", gitversion);
#else
	msg(LOG_INFO, NULL, "started: %s", gitversion);
#endif
	r = smfi_main();
	if (r != MI_SUCCESS)
		msg(LOG_CRIT, NULL, "smfi_main: terminating due to error: %s",strerror(errno));
	else
		msg(LOG_INFO, NULL, "smfi_main: terminating without error");

#ifdef GEOIP2
	if (geoip2_db_path) {
		if (geoip2_closedb() < 0)
			msg(LOG_ERR, NULL,"geoip2_closedb(%s): %s\n",geoip2_db_path,strerror(errno));
	}
#endif

done:
	return (r);
}
