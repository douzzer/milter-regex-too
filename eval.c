#define _GNU_SOURCE

/* $Id: eval.c,v 1.1.1.1 2007/01/11 15:49:52 dhartmei Exp $ */

/*
 * Copyright (c) 2004-2006 Daniel Hartmeier
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

static __attribute__((unused)) const char rcsid[] = "$Id: eval.c,v 1.1.1.1 2007/01/11 15:49:52 dhartmei Exp $";

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <ctype.h>
#include <syslog.h>

#include "milter-regex.h"

#ifdef GEOIP2
#include <stdio.h>
#endif

#ifndef REG_BASIC
#define REG_BASIC	0
#endif

extern int	 yyerror(const char *, ...);
static int	 check_cond(struct context *context, struct cond *, const char *, const char *);
static void	 push_expr_result(struct expr *, int, int *);
static void	 push_cond_result(struct cond *, int, int *);
static int	 build_regex(struct cond_arg *);
#ifdef GEOIP2
static int	 build_geoip2_path(struct cond_arg *);
#endif
static void	 free_expr_list(struct expr_list *, struct expr *);

#if 0
static pthread_mutex_t	 eval_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif
static struct action	 default_action;

int
eval_init(int type)
{
	memset(&default_action, 0, sizeof(default_action));
	default_action.type = type;
	return 0;
}

#define eval_mutex_lock()
#if 0
static void
eval_mutex_lock(void)
{
	int rv = pthread_mutex_lock(&eval_mutex);
	if (rv)
		die_with_errno(rv,"pthread_mutex_lock");
}
#endif

#define eval_mutex_unlock()
#if 0
static void
eval_mutex_unlock(void)
{
	int rv = pthread_mutex_unlock(&eval_mutex);
	if (rv)
		die_with_errno(rv,"pthread_mutex_unlock");
}
#endif

struct ruleset *
create_ruleset(void)
{
	struct ruleset *rs;

	rs = calloc(1, sizeof(struct ruleset));
	if (rs == NULL) {
		yyerror("create_ruleset: calloc: %s", strerror(errno));
		return (NULL);
	}
	return (rs);
}

struct expr *
create_cond_4(struct ruleset *rs, int type, const char *a, const char *b, const char *c, const char *d)
{
	struct cond *cond = NULL;
	struct cond_list *cl = NULL;
	struct expr *expr = NULL;
	struct expr_list *elc = NULL;

	eval_mutex_lock();
	expr = calloc(1, sizeof(struct expr));
	if (expr == NULL)
		goto error;
	elc = calloc(1, sizeof(struct expr_list));
	if (elc == NULL)
		goto error;

	/* if this exact condition was used earlier in the config file, recycle it. */
	for (cl = rs->cond[type]; cl != NULL; cl = cl->next) {
		if ((cl->cond->args[0].src == NULL) != (a == NULL) ||
		    (cl->cond->args[1].src == NULL) != (b == NULL) ||
		    (cl->cond->args[2].src == NULL) != (c == NULL) ||
		    (cl->cond->args[3].src == NULL) != (d == NULL) ||
		    (a != NULL && strcmp(a, cl->cond->args[0].src)) ||
		    (b != NULL && strcmp(b, cl->cond->args[1].src)) ||
		    (c != NULL && strcmp(c, cl->cond->args[2].src)) ||
		    (d != NULL && strcmp(d, cl->cond->args[3].src)))
			continue;
		break;
	}
	if (cl != NULL)
		cond = cl->cond;
	else {
		cl = calloc(1, sizeof(struct cond_list));
		if (cl == NULL)
			goto error;
		cond = calloc(1, sizeof(struct cond));
		if (cond == NULL)
			goto error;

		cond->type = type;

		if (a != NULL) {
			cond->args[0].src = strdup(a);
			if (cond->args[0].src == NULL)
				goto error;
			if (type == COND_COMPARE_CAPTURES) {
				/* nothing to prepare. */
			} else
#ifdef GEOIP2
			if (type == COND_CONNECTGEO) {
				if (build_geoip2_path(&cond->args[0]))
					goto error;
			} else {
#endif
				if (build_regex(&cond->args[0]))
					goto error;
#ifdef GEOIP2
			}
#endif
		}
		if (b != NULL) {
			cond->args[1].src = strdup(b);
			if (cond->args[1].src == NULL)
				goto error;
			if (build_regex(&cond->args[1]))
				goto error;
#ifdef GEOIP2
			if ((type == COND_HEADERGEO) &&
			    (cond->args[1].not || cond->args[1].empty)) {
				yyerror("create_cond_4: 2nd arg (capture arg) must not be empty or negated");
				goto error;
			}
#endif

			if (((type == COND_CAPTURE_ONCE_HEADER) ||
			     (type == COND_CAPTURE_ALL_HEADER) ||
			     (type == COND_CAPTURE_MACRO) ||
			     (type == COND_COMPARE_HEADER) ||
			     (type == COND_COMPARE_CAPTURES)
#ifdef GEOIP2
			     || (type == COND_CAPTURE_ONCE_HEADER_GEO) ||
			     (type == COND_CAPTURE_ALL_HEADER_GEO) ||
			     (type == COND_CAPTURE_MACRO_GEO)
#endif
			     ) &&
			    cond->args[1].not) {
				yyerror("create_cond_4: 2nd arg (capture arg) must not be negated");
				goto error;
			}

		}
		if (c != NULL) {
			cond->args[2].src = strdup(c);
			if (cond->args[2].src == NULL)
				goto error;
			if ((type == COND_CAPTURE_ONCE_HEADER) ||
			    (type == COND_CAPTURE_ALL_HEADER) ||
			    (type == COND_CAPTURE_MACRO) ||
			    (type == COND_COMPARE_HEADER) ||
			    (type == COND_COMPARE_CAPTURES)) {
				/* nothing to prepare. */
			} else
#ifdef GEOIP2
			if ((type == COND_HEADERGEO) ||
			    (type == COND_CAPTURE_ONCE_HEADER_GEO) ||
			    (type == COND_CAPTURE_ALL_HEADER_GEO) ||
			    (type == COND_CAPTURE_MACRO_GEO)) {
				if (build_geoip2_path(&cond->args[2]))
					goto error;
			} else {
#endif
				if (build_regex(&cond->args[2]))
					goto error;
#ifdef GEOIP2
			}
#endif
		}
		if (d != NULL) {
			cond->args[3].src = strdup(d);
			if (cond->args[3].src == NULL)
				goto error;
#ifdef GEOIP2
			if ((type == COND_CAPTURE_ONCE_HEADER_GEO) ||
			    (type == COND_CAPTURE_ALL_HEADER_GEO) ||
			    (type == COND_CAPTURE_MACRO_GEO)) {
				/* nothing to prepare. */
			} else
#endif
			{
				if (build_regex(&cond->args[3]))
					goto error;
				if ((type == COND_COMPARE_CAPTURES) &&
				    cond->args[3].not) {
				  yyerror("create_cond_4: 4th arg (capture arg) must not be negated");
				  goto error;
				}
			}
		}

		cond->idx = rs->maxidx++;
		cl->cond = cond;
		cl->next = rs->cond[type];
		rs->cond[type] = cl;
	}

	expr->type = EXPR_COND;
	expr->cond = cond;
	expr->idx = rs->maxidx++;
	elc->expr = expr;
	elc->next = cond->expr;
	cond->expr = elc;
	eval_mutex_unlock();
	return (expr);

error:
	if (elc != NULL)
		free(elc);
	if (expr != NULL)
		free(expr);
	if (cl != NULL)
		free(cl);
	if (cond != NULL) {
		for (int i=0; i<4; ++i) {
			if (!cond->args[i].empty)
				regfree(&cond->args[i].re);
			if (cond->args[i].src != NULL)
				free(cond->args[i].src);
		}
		free(cond);
	}
	eval_mutex_unlock();
	return (NULL);
}

struct expr *
create_cond(struct ruleset *rs, int type, const char *a, const char *b)
{
  return create_cond_4(rs, type, a, b, NULL, NULL);
}

struct expr *
create_capture(struct ruleset *rs, int type, const char *a, const char *b, const char *c, const char *d, int lineno)
{
	struct expr *cap_expr = create_cond_4(rs, type, a, b, c, d);
	if (cap_expr == NULL)
		return NULL;

	if (cap_expr->cond->expr && cap_expr->cond->expr->next) {
		yyerror("yyparse: duplicate capture expression");
		return NULL;
	}

	struct action *meta = create_action(rs, ACTION_META, "", lineno);
	if (meta == NULL) {
		yyerror("yyparse: create_action");
		return NULL;
	}

	cap_expr->action = meta;

	return cap_expr;
}

struct expr *
create_expr(struct ruleset *rs, int type, struct expr *a, struct expr *b)
{
	struct expr *e = NULL;
	struct expr_list *ela = NULL, *elb = NULL;

	eval_mutex_lock();
	e = calloc(1, sizeof(struct expr));
	if (e == NULL)
		goto error;
	if (a != NULL) {
		ela = calloc(1, sizeof(struct expr_list));
		if (ela == NULL)
			goto error;
	}
	if (b != NULL) {
		elb = calloc(1, sizeof(struct expr_list));
		if (elb == NULL)
			goto error;
	}
	e->type = type;
	e->idx = rs->maxidx++;
	if (a != NULL) {
		e->args[0] = a;
		ela->expr = e;
		ela->next = a->expr;
		a->expr = ela;
	}
	if (b != NULL) {
		e->args[1] = b;
		elb->expr = e;
		elb->next = b->expr;
		b->expr = elb;
	}
	eval_mutex_unlock();
	return (e);

error:
	yyerror("create_expr: calloc: %s", strerror(errno));
	if (elb != NULL)
		free(elb);
	if (ela != NULL)
		free(ela);
	if (e != NULL)
		free(e);
	eval_mutex_unlock();
	return (NULL);
}

struct action *
create_action(struct ruleset *rs, int type, const char *msgtxt, int lineno)
{
	struct action *a = NULL;
	struct action_list *al = NULL;

	eval_mutex_lock();
	a = calloc(1, sizeof(struct action));
	if (a == NULL)
		goto error;
	al = calloc(1, sizeof(struct action_list));
	if (al == NULL)
		goto error;
	a->type = type;
	a->msg = msgtxt == NULL ? NULL : strdup(msgtxt);
	a->idx = rs->maxidx++;
	a->lineno = lineno;
	al->action = a;
	/* tail insert, so actions have same order as file */
	if (rs->action == NULL)
		rs->action = al;
	else {
		struct action_list *t = rs->action;

		while (t->next != NULL)
			t = t->next;
		t->next = al;
	}
	eval_mutex_unlock();
	return (a);

error:
	yyerror("create_action: calloc: %s", strerror(errno));
	if (al != NULL)
		free(al);
	if (a != NULL)
		free(a);
	eval_mutex_unlock();
	return (NULL);
}

static struct action *
eval_cond_1(struct context *context, int type,
    const char *a, const char *b)
{
	struct ruleset *rs = context->rs;
	int *res = context->res;

	struct cond_list *cl;
	struct action_list *al;

	int initial_captures_change_count = context->captures_change_count;

again:

	for (cl = rs->cond[type]; cl != NULL; cl = cl->next) {
		int r;
		if (res[cl->cond->idx] != VAL_UNDEF)
			continue;
		r = check_cond(context, cl->cond, a, b);
		if (r < 0)
			return (NULL);
		else if (!r)
			push_cond_result(cl->cond, VAL_TRUE, res);
	}
	for (al = rs->action; al != NULL; al = al->next) {
		if (al->action->type == ACTION_META)
			continue;
		if (res[al->action->idx] == VAL_TRUE)
			return (al->action);
	}

	if ((type != COND_COMPARE_CAPTURES) &&
	    (context->captures_change_count != initial_captures_change_count)) {
		type = COND_COMPARE_CAPTURES;
		goto again;
	}

	return (NULL);
}

static long long int now_usecs(void) {
	if (! debug)
		return 0;
	struct timeval now;
	(void)gettimeofday(&now,0);
	return ((long long int)now.tv_sec * 1000000LL) + (long long int)now.tv_usec;
}

struct action *
eval_cond(struct context *context, int type,
    const char *a, const char *b)
{
	long long int start_at = now_usecs();
	eval_mutex_lock();
	struct action *ret = eval_cond_1(context,type,a,b);
	eval_mutex_unlock();
	if (debug)
		context->eval_time_cum += now_usecs() - start_at;
	return ret;
}

struct action *
eval_end(struct context *context, int type, __attribute__((unused)) int max)
{
	long long int start_at = now_usecs();
	struct ruleset *rs = context->rs;
	int *res = context->res;
	struct action *ret = &default_action;

	struct cond_list *cl;
	struct action_list *al;

	eval_mutex_lock();

	context->last_phase_done = type;

	for (cl = rs->cond[type]; cl != NULL; cl = cl->next)
		if (res[cl->cond->idx] == VAL_UNDEF)
			push_cond_result(cl->cond, VAL_FALSE, res);
	for (al = rs->action; al != NULL; al = al->next) {
		if (al->action->type == ACTION_META)
			continue;
		if (res[al->action->idx] == VAL_TRUE) {
			eval_mutex_unlock();
			if (debug)
				context->eval_time_cum += now_usecs() - start_at;
			return (al->action);
		}
	}
#if 0
	for (type = max; type < COND_MAX; ++type) {
		if (type == COND_PHASEDONE)
			continue;
		for (cl = rs->cond[type]; cl != NULL; cl = cl->next)
			if (res[cl->cond->idx] == VAL_UNDEF)
				break;
	}
#endif

	ret = eval_cond_1(context, COND_PHASEDONE, 0, 0);

	eval_mutex_unlock();
	if (debug)
		context->eval_time_cum += now_usecs() - start_at;
	return ret;
}

void
eval_clear(struct context *context, int type)
{
	long long int start_at = now_usecs();
	struct ruleset *rs = context->rs;
	int *res = context->res;

	struct cond_list *cl;

	eval_mutex_lock();
	for (; type < COND_MAX; ++type)
		for (cl = rs->cond[type]; cl != NULL; cl = cl->next)
			push_cond_result(cl->cond, VAL_UNDEF, res);
	for (struct action_list *al = rs->action; al != NULL; al = al->next)
		res[al->action->idx] = VAL_UNDEF;
	eval_mutex_unlock();
	if (debug)
		context->eval_time_cum += now_usecs() - start_at;
}

int insert_kv_binding(struct context *context, const char *key, const char *val, size_t val_len, struct kv_binding **point) {
	struct kv_binding *new_kv = malloc(sizeof *new_kv + val_len + 1);
	struct kv_binding *local_point = 0;
	if (! new_kv)
		return -1;
	if (! point)
	  point = &local_point;
	new_kv->key = key;
	new_kv->val_len = val_len;
	memcpy(new_kv->val, val, val_len);
	new_kv->val[val_len] = 0;
	if (! *point) {
		for (struct kv_binding *i = context->captures; i; i = i->next) {
			if (! strcmp(i->key,key))
				*point = i;
			else if (*point)
				break;
		}
	}
	if (*point) {
		new_kv->prev = *point;
		new_kv->next = (*point)->next;
		(*point)->next = new_kv;
	} else {
		new_kv->prev = 0;
		new_kv->next = context->captures;
		context->captures = new_kv;
	}
	if (new_kv->next)
		new_kv->next->prev = new_kv;
	*point = new_kv;

	msg(LOG_DEBUG, context, "inserted KV \"%s\" = \"%.*s\"", key, (int)val_len, val);
	++context->captures_change_count;

	return 0;
}

const char *get_kv_binding_next(const struct kv_binding **next) {
	if (! *next)
		return 0;
	const char *ret = (*next)->val;
	if ((*next)->next && (! strcmp((*next)->key, (*next)->next->key)))
		*next = (*next)->next;
	else
		*next = 0;
	return ret;
}

const char *get_kv_binding_first(struct context *context, const char *key, const struct kv_binding **next) {
	for (struct kv_binding *i = context->captures; i; i = i->next) {
		if (! strcmp(i->key,key)) {
			*next = i;
			return get_kv_binding_next(next);
		}
	}
	return 0;
}

void free_kv_bindings(struct kv_binding *list) {
	while (list) {
		struct kv_binding *next = list->next;
		free(list);
		list = next;
	}
}

static int compare_values(const char *first, size_t first_len, struct cond_arg *first_cond,
			  const char *second, size_t second_len, struct cond_arg *second_cond) {

	if (first_len == second_len)
		return memcmp(first, second, first_len);
	else if (second_len > first_len) {
		if (first_cond->compare_as_suffix) {
			if (! memcmp(first, second + (second_len - first_len), first_len))
				return 0;
		}
		if (first_cond->compare_as_dname_suffix) {
			if ((*(second + (second_len - first_len) - 1) == '.') &&
			    (! memcmp(first, second + (second_len - first_len), first_len)))
				return 0;
		}
		if (first_cond->compare_as_prefix) {
			if (! memcmp(first, second, first_len))
				return 0;
		}
		if (first_cond->compare_as_dname_prefix) {
			if ((second[first_len] == '.') &&
			    (! memcmp(first, second, first_len)))
				return 0;
		}
	} else {
		if (second_cond->compare_as_suffix) {
			if (! memcmp(second, first + (first_len - second_len), second_len))
				return 0;
		}
		if (second_cond->compare_as_dname_suffix) {
			if ((*(first + (first_len - second_len) - 1) == '.') &&
			    (! memcmp(second, first + (first_len - second_len), second_len)))
				return 0;
		}
		if (second_cond->compare_as_prefix) {
			if (! memcmp(second, first, second_len))
				return 0;
		}
		if (second_cond->compare_as_dname_prefix) {
			if ((first[second_len] == '.') &&
			    (! memcmp(second, first, second_len)))
				return 0;
		}
	}
	return 1;
}

static int get_envelope_member(struct context *context, const char *name, const char **value, size_t *value_len) {
	if (! name)
		return -EINVAL;

#define CHECK_ENVELOPE(checkname, membername) if (! strcmp(name,checkname)) { *value = context->membername; *value_len = strnlen(context->membername, sizeof context->membername); return 0; }

	switch(name[0]) {
	case 'c':
		CHECK_ENVELOPE("client_resolve", client_resolve);
		CHECK_ENVELOPE("connect:hostname", host_name);
		CHECK_ENVELOPE("connect:address", host_addr);
#ifdef GEOIP2
		if (! strcmp(name,"connect:geoip")) {
			if (! context->geoip2_result_summary) {
				if (prime_geoip2(context) == 0)
					(void)geoip2_refresh_summary(context);
			}
			if (context->geoip2_result_summary) {
				*value = context->geoip2_result_summary;
				*value_len = strlen(*value);
				return 0;
			} else
				return -ENOENT;
		}
#endif
		return -ENOENT;
	case 'e':
		CHECK_ENVELOPE("envfrom", env_from);
		CHECK_ENVELOPE("envrcpt", env_rcpt);
		return -ENOENT;
	case 'f':
		CHECK_ENVELOPE("from", hdr_from);
		return -ENOENT;
	case 'h':
		CHECK_ENVELOPE("helo", helo);
		return -ENOENT;
	case 'l':
		if (! strncmp(name,"literal:",strlen("literal:"))) {
			*value = name + strlen("literal:");
			*value_len = strlen(*value);
			return 0;
		}
		return -ENOENT;
	case 'm':
		CHECK_ENVELOPE("message_id", message_id);
		CHECK_ENVELOPE("my_name", my_name);
		return -ENOENT;
	case 's':
		CHECK_ENVELOPE("subject", hdr_subject);
		return -ENOENT;
	case 't':
		CHECK_ENVELOPE("tls_status", tls_status);
		CHECK_ENVELOPE("to", hdr_to);
		return -ENOENT;
	default:
		return -ENOENT;
	}
}

static int
check_cond(struct context *context, struct cond *c, const char *a, const char *b)
{
	++context->check_cond_count;

	switch (c->type) {

	case COND_PHASEDONE: {
		if ((! c->args[0].src) || c->args[0].empty) /* nonsense existence check */
			return c->args[0].not;
		if (context->last_phase_done == COND_NONE)
			return 1;
		const char *last_phase_done = lookup_cond_name(context->last_phase_done);
		int r = regexec(&c->args[0].re, last_phase_done, 0, NULL, 0);
		if (r && r != REG_NOMATCH)
			return -1;
		else if ((r == REG_NOMATCH) != c->args[0].not)
			return 1;
		else
			return 0;
	}

	case COND_CAPTURE_ONCE_HEADER:
	case COND_CAPTURE_ALL_HEADER: {
		/* capture_header <header_LHS_match_re> <header_RHS_selector_re> <varname> */

		if ((! a) || (! b))
			return -1;

		if (! c->args[0].empty) {
			int r = regexec(&c->args[0].re, a, 0, NULL, 0);
			if (r && r != REG_NOMATCH)
				return -1;
			if ((r == REG_NOMATCH) != c->args[0].not)
				return 1;
		}

		ssize_t b_len_left = (ssize_t)strlen(b);

		if (c->args[1].empty) {
			insert_kv_binding(context, c->args[2].src, b, b_len_left, 0);
			return c->type == COND_CAPTURE_ALL_HEADER; /* return false to arrange for calls on every header regardless of earlier match. */
		}

		const char *b_ptr = b;
		regmatch_t matches[8];
		struct kv_binding *point = 0;
		int n_inserted = 0;

		while (b_len_left > 0) {
			int r = regexec(&c->args[1].re, b_ptr, sizeof matches / sizeof matches[0], matches, (b_ptr != b) ? REG_NOTBOL : 0);
			if (r) {
				if (r != REG_NOMATCH)
					return -1;
				else
					break;
			}

			for (int i=1;;) {
				if (matches[i].rm_so != -1) {
					insert_kv_binding(context, c->args[2].src, b + matches[i].rm_so, matches[i].rm_eo - matches[i].rm_so, &point);
					++n_inserted;
				}
				if (i == 0)
					break;
				++i;
				if (i == (int)(sizeof matches / sizeof matches[0])) {
					if (! n_inserted)
						i = 0;
					else
						break;
				}
			}

			if (! c->args[1].global)
			  break;

			b_len_left -= matches[0].rm_eo;
			b_ptr += matches[0].rm_eo;
		}

		if (c->type == COND_CAPTURE_ALL_HEADER)
			return 1; /* return false to arrange for calls on every header regardless of earlier match. */
		else
			return (n_inserted > 0) ? 0 : 1;
	}

#ifdef GEOIP2
	case COND_CAPTURE_ONCE_HEADER_GEO:
	case COND_CAPTURE_ALL_HEADER_GEO: {
		/* capture_header_geo <header_LHS_match_re> <header_RHS_selector_re> <geo_ip_path> <varname> */

		return -1;
	}
#endif

	case COND_CAPTURE_MACRO: {
		/* capture_macro <macro_LHS_match_re> <macro_RHS_selector_re> <varname> */

		if ((! a) || (! b))
			return -1;

		if (! c->args[0].empty) {
			int r = regexec(&c->args[0].re, a, 0, NULL, 0);
			if (r && r != REG_NOMATCH)
				return -1;
			if ((r == REG_NOMATCH) != c->args[0].not)
				return 1;
		}

		ssize_t b_len_left = (ssize_t)strlen(b);

		if (c->args[1].empty) {
		  insert_kv_binding(context, c->args[2].src, b, b_len_left, 0);
		  return 0;
		}

		const char *b_ptr = b;
		regmatch_t matches[8];
		struct kv_binding *point = 0;
		int n_inserted = 0;

		while (b_len_left > 0) {
			int r = regexec(&c->args[1].re, b_ptr, sizeof matches / sizeof matches[0], matches, (b_ptr != b) ? REG_NOTBOL : 0);
			if (r) {
				if (r != REG_NOMATCH)
					return -1;
				else
					break;
			}

			for (int i=1;;) {
				if (matches[i].rm_so != -1) {
					insert_kv_binding(context, c->args[2].src, b + matches[i].rm_so, matches[i].rm_eo - matches[i].rm_so, &point);
					++n_inserted;
				}
				if (i == 0)
					break;
				++i;
				if (i == (int)(sizeof matches / sizeof matches[0])) {
					if (! n_inserted)
						i = 0;
					else
						break;
				}
			}

			if (! c->args[1].global)
			  break;

			b_len_left -= matches[0].rm_eo;
			b_ptr += matches[0].rm_eo;
		}

		return (n_inserted > 0) ? 0 : 1;
	}

#ifdef GEOIP2
	case COND_CAPTURE_MACRO_GEO: {
		/* capture_macro_geo <macro_LHS_match_re> <macro_RHS_selector_re> <geo_ip_path> <varname> */

		return -1;
	}
#endif

	case COND_COMPARE_HEADER: {
		/* <header_LHS_match_re> <header_RHS_selector_re> [!]<connect:host|connect:addr|helo|envfrom|envrcpt|var:name> [macro_RHS_selector_re] */
	  return -1;
	}

	case COND_COMPARE_CAPTURES: {
		/* compare_captures <connect:host|connect:addr|helo|envfrom|envrcpt|var:name> <value_selector_re1> <connect:host|connect:addr|helo|envfrom|envrcpt|var:name> <value_selector_re2> */
		/* (cond->args[1].src and [3].src can safely be null, though that's not currently used.) */

		/* test passes if any of vals for the first key equal any of the vals for the second. */

		/*
		 * note this is quite an elaborate nested loop proposition.  not only
		 * is there iteration among all members of each set, but for the _re
		 * variant, for each member there is iteration through captures, not
		 * just through captures via a multi-capture RE, but for global-tagged
		 * REs, through all captures tiling the RE across each member.  the
		 * cumulative iterator depth is 6, but looks like 4 because the two
		 * stages of RE iteration are done with goto.
		 */

		const struct kv_binding *first_operand_i, *second_operand_i;
		const char *first_operand_preselection = get_kv_binding_first(context, c->args[0].src, &first_operand_i);
		size_t first_operand_preselection_len = 0;
		if (! first_operand_preselection) {
		  if (get_envelope_member(context, c->args[0].src, &first_operand_preselection, &first_operand_preselection_len) < 0)
		    break;
		  first_operand_i = 0;
		}

		const char *second_operand_preselection = get_kv_binding_first(context, c->args[2].src, &second_operand_i);
		size_t second_operand_preselection_len = 0;
		if (! second_operand_preselection) {
		  if (get_envelope_member(context, c->args[2].src, &second_operand_preselection, &second_operand_preselection_len) < 0)
		    break;
		  second_operand_i = 0;
		}

		for (; first_operand_preselection; first_operand_preselection = first_operand_i ? get_kv_binding_next(&first_operand_i) : 0) {
		  const char *first_operand;
		  size_t first_operand_len;

		  ssize_t first_operand_len_left = first_operand_preselection_len ? (ssize_t)first_operand_preselection_len : (ssize_t)strlen(first_operand_preselection);
		  const char *first_operand_ptr = first_operand_preselection;
		  regmatch_t first_operand_matches[8];
		  int first_operand_matches_i = 0;
		  int first_operand_n_captures = 0;

		  while (first_operand_len_left > 0) {

		    if (c->args[1].src && ! c->args[1].empty) {
		      /* if multiple selections, need to iterate through the selections. */

		      if (first_operand_matches_i == 0) {
			int r = regexec(&c->args[1].re,
					first_operand_ptr,
					sizeof first_operand_matches / sizeof first_operand_matches[0],
					first_operand_matches,
					(first_operand_ptr != first_operand_preselection) ? REG_NOTBOL : 0);
			if (r) {
			  if (r != REG_NOMATCH)
			    return -1;
			  else
			    goto continue_0;
			}

			first_operand_len_left -= first_operand_matches[0].rm_eo;
			first_operand_ptr += first_operand_matches[0].rm_eo;

		      }

		    next_first_operand_match:

		      ++first_operand_matches_i;

		      if ((first_operand_matches_i == (int)(sizeof first_operand_matches / sizeof first_operand_matches[0])) &&
			  (! first_operand_n_captures))
			      first_operand_matches_i = 0;
		      else if ((! first_operand_matches_i) ||
			       (first_operand_matches_i >= (int)(sizeof first_operand_matches / sizeof first_operand_matches[0]))) {
		      first_operand_matches_done:
			if (! c->args[1].global)
			  break;

			first_operand_matches_i = 0;
			first_operand_n_captures = 0;

			continue;
		      }
		      if (first_operand_matches[first_operand_matches_i].rm_so == -1) {
			if (! first_operand_matches_i)
			  goto first_operand_matches_done;
			else
			  goto next_first_operand_match;
		      }

		      ++first_operand_n_captures;

		      first_operand = first_operand_preselection + first_operand_matches[first_operand_matches_i].rm_so;
		      first_operand_len = first_operand_matches[first_operand_matches_i].rm_eo - first_operand_matches[first_operand_matches_i].rm_so;

		    } else {

		      first_operand = first_operand_preselection;
		      first_operand_len = first_operand_len_left;
		      first_operand_len_left = 0;

		    }

		    for (;
			 second_operand_preselection;
			 second_operand_preselection = second_operand_i ? get_kv_binding_next(&second_operand_i) : 0) {
		      const char *second_operand;
		      size_t second_operand_len;

		      ssize_t second_operand_len_left =
			      second_operand_preselection_len ?
			      (ssize_t)second_operand_preselection_len :
			      (ssize_t)strlen(second_operand_preselection);
		      const char *second_operand_ptr = second_operand_preselection;
		      regmatch_t second_operand_matches[8];
		      int second_operand_matches_i = 0;
		      int second_operand_n_captures = 0;

		      while (second_operand_len_left > 0) {

			if (c->args[3].src && ! c->args[3].empty) {
			  /* if multiple selections, need to iterate through the selections. */

			  if (second_operand_matches_i == 0) {
			    int r = regexec(&c->args[3].re, second_operand_ptr,
					    sizeof second_operand_matches / sizeof second_operand_matches[0],
					    second_operand_matches,
					    (second_operand_ptr != second_operand_preselection) ? REG_NOTBOL : 0);
			    if (r) {
			      if (r != REG_NOMATCH)
				return -1;
			      else
				goto continue_2;
			    }

			    second_operand_len_left -= second_operand_matches[0].rm_eo;
			    second_operand_ptr += second_operand_matches[0].rm_eo;

			  }

			next_second_operand_match:

			  ++second_operand_matches_i;

			  if ((second_operand_matches_i == (int)(sizeof second_operand_matches / sizeof second_operand_matches[0])) &&
			      (! second_operand_n_captures))
			    second_operand_matches_i = 0;
			  else if (second_operand_matches_i >= (int)(sizeof second_operand_matches / sizeof second_operand_matches[0])) {
			  second_operand_matches_done:
			    if (! c->args[3].global)
			      goto continue_2;

			    second_operand_matches_i = 0;
			    second_operand_n_captures = 0;
			    continue;
			  }
			  if (second_operand_matches[second_operand_matches_i].rm_so == -1) {
			    if (! second_operand_matches_i)
			      goto second_operand_matches_done;
			    else
			      goto next_second_operand_match;
			  }

			  ++second_operand_n_captures;

			  second_operand = second_operand_preselection + second_operand_matches[second_operand_matches_i].rm_so;
			  second_operand_len = second_operand_matches[second_operand_matches_i].rm_eo - second_operand_matches[second_operand_matches_i].rm_so;

			} else {

			  second_operand = second_operand_preselection;
			  second_operand_len = second_operand_len_left;
			  second_operand_len_left = 0;

			}

			if (compare_values(first_operand, first_operand_len, &c->args[1], second_operand, second_operand_len, &c->args[3]) == 0)
			  return 0;

			/* end iteration for RE matches inside the current second operand */
		      }

		    continue_2:
		      ;

		      /* end iteration through values for the second operand */
		    }

		    if (! c->args[1].src)
		      break;

		    /* end iteration for RE matches inside the current first operand */
		  }


		continue_0:
		  ;
		  /* end iteration through values for the first operand */
		}

		/* null intersection, return false and try again after the next KV insertion. */
		return 1;
	}

#ifdef GEOIP2
	case COND_CONNECTGEO: {

		if ((! c->args[0].geoip2_path[0]) || (! geoip2_db_path))
			return 0; /* GeoIP2 not configured or not working -- fail open. */
		if (context->geoip2_lookup_ret < 0)
			return c->args[1].not ? 0 : 1; /* IP lookup failed -- fail closed. */
		if (! context->geoip2_result) {
			context->geoip2_result = geoip2_lookup(geoip2_db_path, context->host_addr, &context->geoip2_result_cache, 0);
			if (! context->geoip2_result) {
				context->geoip2_lookup_ret = -1;
				return c->args[1].not ? 0 : 1;
			}
		}

		struct MMDB_entry_data_list_s *leaf;
		if (geoip2_pick_leaf(context->geoip2_result, (const char * const *)c->args[0].geoip2_path, &leaf) == 0) {
			int matched = 1; /* initialize to no-match. */

			if ((! c->args[1].src) || c->args[1].empty) { /* just a leaf existence check */
				matched = c->args[1].not ? 1 : 0;
				goto out;
			}

			for (struct MMDB_entry_data_list_s *leaf_i = leaf;
			     leaf_i;
			     ) {
				char leafbuf[256];
				const char *s;
				int s_len;

				if (geoip2_iterate_leaf(&leaf_i, leafbuf, sizeof leafbuf, &s, &s_len) != 0)
					break;
				char *s_nulltermed = malloc((size_t)s_len+1); /* avoiding strndup() for portability. */
				if (! s_nulltermed)
					continue;
				memcpy(s_nulltermed,s,(size_t)s_len);
				s_nulltermed[s_len] = 0;
				int r = regexec(&c->args[1].re, s_nulltermed, 0, NULL, 0);
				if (r && r != REG_NOMATCH)
					matched = -1;
				else if ((r == REG_NOMATCH) == c->args[1].not)
					matched = 0;
				free(s_nulltermed);
				if (matched <= 0)
					break;
			}
		out:
			if (geoip2_free_leaf(leaf) < 0)
				perror("geoip2_free_leaf");
			return matched;
		} else
			return c->args[1].not ? 0 : 1; /* leaf lookup failed -- fail closed. */
	}

	case COND_HEADERGEO: {

/* headergeo /header-name-pattern/ /address-match-pattern/ /geo/record/path /geo-record-pattern/ */

		if ((! c->args[2].geoip2_path[0]) || (! geoip2_db_path))
			return 0; /* GeoIP2 not configured or not working -- fail open. */

		if (! b)
			return -1;
		if (c->args[0].empty) {
			if (a) {
				if (c->args[0].not)
					return 1;
			} else {
				if (! c->args[0].not)
					return 1;
			}
		} else {
			if (a == NULL)
				return -1;
		}

		if (! c->args[0].empty) {
			int r = regexec(&c->args[0].re, a, 0, NULL, 0);
			if (r && r != REG_NOMATCH)
				return -1;
			if ((r == REG_NOMATCH) != c->args[0].not)
				return 1;
		}

		{
			ssize_t b_len_left = (ssize_t)strlen(b);
			const char *b_ptr = b;
			regmatch_t addr_matches[8];
			char abuf[64];

			while (b_len_left > 0) {
				int r = regexec(&c->args[1].re, b_ptr, sizeof addr_matches / sizeof addr_matches[0], addr_matches, (b_ptr != b) ? REG_NOTBOL : 0);
				if (r) {
					if (r != REG_NOMATCH)
						return -1;
					else
						return 1;
				}

				for (int i=1; i<8; ++i) {
					if (addr_matches[i].rm_so == -1)
						continue;
					size_t match_len = addr_matches[i].rm_eo - addr_matches[i].rm_so;
					if (match_len >= sizeof abuf)
						continue;
					if (match_len < 4)
						continue;
					memcpy(abuf, b_ptr + addr_matches[i].rm_so, match_len);
					abuf[match_len] = 0;
					if ((strspn(abuf,"0123456789.") != match_len) &&
					    (strspn(abuf,"0123456789abcdefABCDEF:") != match_len))
						continue;

					struct MMDB_lookup_result_s *geo = geoip2_lookup(geoip2_db_path, abuf, &context->geoip2_result_cache, 1);

					if (! geo)
						continue;

					struct MMDB_entry_data_list_s *leaf;
					if (geoip2_pick_leaf(geo, (const char * const *)c->args[2].geoip2_path, &leaf) == 0) {
						int matched = 1; /* initialize to no-match. */

						if ((! c->args[3].src) || c->args[3].empty) { /* just a leaf existence check */
							matched = c->args[3].not ? 1 : 0;
							goto out2;
						}

						for (struct MMDB_entry_data_list_s *leaf_i = leaf;
						     leaf_i;
							) {
							char leafbuf[256];
							const char *s;
							int s_len;

							if (geoip2_iterate_leaf(&leaf_i, leafbuf, sizeof leafbuf, &s, &s_len) != 0)
								break;
							char *s_nulltermed = malloc((size_t)s_len+1); /* avoiding strndup() for portability. */
							if (! s_nulltermed)
								continue;
							memcpy(s_nulltermed,s,(size_t)s_len);
							s_nulltermed[s_len] = 0;
							r = regexec(&c->args[3].re, s_nulltermed, 0, NULL, 0);
							if (r && r != REG_NOMATCH)
								matched = -1;
							else if ((r == REG_NOMATCH) == c->args[3].not)
								matched = 0;
							free(s_nulltermed);
							if (matched <= 0)
								break;
						}
					out2:
						if (geoip2_free_leaf(leaf) < 0)
							perror("geoip2_free_leaf");
						if (! matched)
							return matched;
					}
				}

				if (! c->args[1].global)
					break;

				b_len_left -= addr_matches[0].rm_eo;
				b_ptr += addr_matches[0].rm_eo;
			}
		}

		return c->args[3].not ? 0 : 1;
	}
#endif

	default:
		break;
	}

	for (int i = 0; i < 2; ++i) {
		const char *d = i ? b : a;
		int r;
		if (c->args[i].src == NULL)
			continue;
		if (c->args[i].empty) {
			/* if the test value is set, the result is pass for // and fail for //n .
			 * if the test value is null, the result is pass for //n and fail for // .
			 * but with an empty regexp, the result is never error.  effectively,
			 * //n is a test for the null pointer.
			 */
			if (d) {
				if (c->args[i].not)
					return 1;
				else
					continue;
			} else {
				if (c->args[i].not)
					continue;
				else
					return 1;
			}
		}
		if (d == NULL)
			return (-1);
		r = regexec(&c->args[i].re, d, 0, NULL, 0);
		if (r && r != REG_NOMATCH)
			return (-1);
		if ((r == REG_NOMATCH) != c->args[i].not)
			return (1);
	}
	return (0);
}

static void
push_expr_result(struct expr *e, int val, int *res)
{
	struct expr_list *el;

	if (res[e->idx] == val)
		return;
	res[e->idx] = val;
	if (e->action != NULL && val == VAL_TRUE)
		res[e->action->idx] = val;
	for (el = e->expr; el != NULL; el = el->next) {
		struct expr *p = el->expr;

		switch (p->type) {
		case EXPR_AND:
			if (res[p->args[0]->idx] == VAL_TRUE &&
			    res[p->args[1]->idx] == VAL_TRUE)
				push_expr_result(p, VAL_TRUE, res);
			else if (res[p->args[0]->idx] == VAL_FALSE ||
			    res[p->args[1]->idx] == VAL_FALSE)
				push_expr_result(p, VAL_FALSE, res);
			else
				push_expr_result(p, VAL_UNDEF, res);
			break;
		case EXPR_OR:
			if (res[p->args[0]->idx] == VAL_TRUE ||
			    res[p->args[1]->idx] == VAL_TRUE)
				push_expr_result(p, VAL_TRUE, res);
			else if (res[p->args[0]->idx] == VAL_FALSE &&
			    res[p->args[1]->idx] == VAL_FALSE)
				push_expr_result(p, VAL_FALSE, res);
			else
				push_expr_result(p, VAL_UNDEF, res);
			break;
		case EXPR_NOT:
			if (val == VAL_TRUE)
				push_expr_result(p, VAL_FALSE, res);
			else if (val == VAL_FALSE)
				push_expr_result(p, VAL_TRUE, res);
			else
				push_expr_result(p, VAL_UNDEF, res);
			break;
		default:
			break;
		}
	}
}

static void
push_cond_result(struct cond *c, int val, int *res)
{
	struct expr_list *el;

	if (res[c->idx] == val)
		return;
	res[c->idx] = val;
	for (el = c->expr; el != NULL; el = el->next) {
		struct expr *e = el->expr;

		if (e->type != EXPR_COND)
			continue;
		push_expr_result(e, val, res);
	}
}

static int
build_regex(struct cond_arg *a)
{
	char del;
	const char *s = a->src, *t;
#ifdef USE_PCRE2
	int flags = REG_DOTALL; /* ". matches anything including NL" */
#else
	int flags = REG_EXTENDED;
#endif

	a->empty = 1;
	a->not = 0;
	while (*s == ' ' || *s == '\t')
		s++;
	if (!*s) {
		yyerror("build_regex: empty argument");
		return (1);
	}
	del = *s++;
	t = s;
	while (*s && *s != del)
		s++;
	if (!*s) {
		yyerror("build_regex: missing closing delimiter %s", a->src);
		return (1);
	}

	for (const char *flags_i = s+1; *flags_i; ++flags_i) {
		switch (*flags_i) {
		case 'b':
#ifdef USE_PCRE2
			yyerror("regex flag b (basic) used but not allowed when USE_PCRE2, in %s", a->src);
			return (1);
#else
			flags |= REG_BASIC;
			flags &= ~REG_EXTENDED;
#endif
			break;
		case 'e':
			break;
		case 'i':
			flags |= REG_ICASE;
			break;
		case 'n':
			a->not = 1;
			break;
		case 'g':
			a->global = 1;
			break;

		case 'p':
			a->compare_as_prefix = 1;
			break;
		case 'P':
			a->compare_as_dname_prefix = 1;
			break;
		case 's':
			a->compare_as_suffix = 1;
			break;
		case 'S':
			a->compare_as_dname_suffix = 1;
			break;

		default:
			yyerror("invalid flag %c in %s", *flags_i, a->src);
			return (1);
		}
	}

	if (s == t) {
		if ((flags&REG_ICASE) || a->global) {
			yyerror("build_regex: nonsensical flag(s) %s associated with empty expression",
				a->src);
			return (1);
		}
	} else {
		char *u;
		int r;

#if defined(__BSD_VISIBLE) && !defined(USE_PCRE2)
		/* kludge until migration to PCRE2 */
		{
			int n_wordedges = 0;
			for (const char *cp = t; cp < s; ++cp) {
				if ((*cp == '\\') && ((*(cp+1) == 'b') || (*(cp+1) == '<') || (*(cp+1) == '>')))
					++n_wordedges;
			}
			u = malloc(s - t + 1 + (n_wordedges * (sizeof "[[:<:]]" - sizeof "\\b")));
			for (char *in = (char *)t, *out = u; ; ) {
				if (in == s) {
					*out = 0;
					break;
				}
				if (*in == '\\') {
					switch (*(in+1)) {
					case 'b':
						/* guesswork */
						if (isalnum(*(in+2)) || (*(in+2) == '_') || (*(in+2) == '(') || (*(in+2) == '['))
							strcpy(out,"[[:<:]]");
						else
							strcpy(out,"[[:>:]]");
						break;
					case '<':
						strcpy(out,"[[:<:]]");
						break;
					case '>':
						strcpy(out,"[[:>:]]");
						break;
					default:
						*out++ = *in++;
						continue;
					}
					out += strlen("[[:<:]]");
					in += 2;
				} else
					*out++ = *in++;
			}
		}
#else
		u = malloc(s - t + 1);
		if (u == NULL) {
			yyerror("build_regex: malloc: %s", strerror(errno));
			return (1);
		}
		memcpy(u, t, s - t);
		u[s - t] = 0;
#endif
		s++;
		r = regcomp(&a->re, u, flags);
		if (r) {
			char e[8192];

			regerror(r, &a->re, e, sizeof(e));
			yyerror("regcomp: %s: %s\n", u, e);
			free(u);
			return (1);
		}
		free(u);
		a->empty = 0;
	}

	return (0);
}

#ifdef GEOIP2
static int
build_geoip2_path(struct cond_arg *a)
{
	a->empty = 1;

	if (! (a->geoip2_buf = strdup(a->src))) {
		yyerror("build_geoip2_path: %s",strerror(errno));
		return 1;
	}

	char *s = a->geoip2_buf;
	char delim;

	while (*s == ' ' || *s == '\t')
		s++;
	if (!*s) {
		yyerror("build_geoip2_path: empty argument");
		return 1;
	}
	delim = *s++;

	size_t path_n = 0;
	for (;;) {
		if (path_n == (sizeof a->geoip2_path / sizeof a->geoip2_path[0]) - 1) {
			yyerror("build_geoip2_path: too many path elements (max %lu)",(sizeof a->geoip2_path / sizeof a->geoip2_path[0]) - 1);
			return 1;
		}
		a->geoip2_path[path_n++] = s;
		if (! (s=strchr(s,delim)))
			break;
		*s++ = 0;
		if (! *s)
			break;
	}

	return 0;
}
#endif

static void
free_expr_list(struct expr_list *el, struct expr *a)
{
	struct expr_list *eln;

	while (el != NULL) {
		struct expr *e = el->expr;

		eln = el->next;
		if (e != NULL) {
			int i, used = 0;

			for (i = 0; i < 2; ++i)
				if (e->args[i] != NULL) {
					if (e->args[i] == a)
						e->args[i] = NULL;
					else
						used = 1;
				}
			if (!used) {
				free_expr_list(e->expr, e);
				free(e);
			}
		}
		free(el);
		el = eln;
	}
}

void
free_ruleset(struct ruleset *rs)
{
	int i;
	struct action_list *al, *aln;

	eval_mutex_lock();
	if (rs == NULL || rs->refcnt) {
		eval_mutex_unlock();
		return;
	}
	for (i = 0; i < COND_MAX; ++i) {
		struct cond_list *cl = rs->cond[i], *cln;

		while (cl != NULL) {
			struct cond *c = cl->cond;

			cln = cl->next;
			if (c != NULL) {
				int j;

				for (j = 0; j < 4; ++j)
					if (c->args[j].src != NULL) {
						free(c->args[j].src);
						if (!c->args[j].empty)
							regfree(&c->args[j].re);
#ifdef GEOIP2
						else if (c->args[j].geoip2_buf)
							free(c->args[j].geoip2_buf);
#endif
					}
				free_expr_list(c->expr, NULL);
				free(c);
			}
			free(cl);
			cl = cln;
		}
	}
	al = rs->action;
	while (al != NULL) {
		struct action *a = al->action;

		aln = al->next;
		if (a != NULL) {
			if (a->msg != NULL)
				free(a->msg);
			free(a);
		}
		free(al);
		al = aln;
	}
	free(rs);
	eval_mutex_unlock();
}
