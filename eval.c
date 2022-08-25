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
static void	 push_expr_result(struct context *context, struct expr *, int);
static void	 push_cond_result(struct context *context, struct cond *, int);
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

static const char *lookup_res_name(int resval) {
	switch(resval) {
	case VAL_UNDEF: return "UNDEF";
	case VAL_TRUE: return "TRUE";
	case VAL_FALSE: return "FALSE";
	default: return "BAD";
	}
}

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

static void append_expr_to_list(struct expr_list *elc, struct expr_list **list) {
	/* use tail insert for exprs too, to keep context.res in order of config file appearance (modulo duplicates).  after
	 * unreverse_ruleset_cond_list(), evaluation will proceed in the
	 * order designated by the config file.
	 *
	 * actions have always been tail-inserted, and that is what drives the actual outcome of evaluation.
	 */
	elc->next = NULL;
	if (*list)	{
		struct expr_list *elp = *list, *el = elp->next;
		while (el) {
			elp = el;
			el = el->next;
		}
		elp->next = elc;
	} else
		*list = elc;
}

static cond_t phase_of_envelope_member(const char *name);

struct expr *
create_cond_4(struct ruleset *rs, cond_t type, const char *a, const char *b, const char *c, const char *d, int lineno, int colno)
{
	struct cond *cond = NULL;
	struct cond_list *cl = NULL;
	struct expr *expr = NULL;
	struct expr_list *elc = NULL;

	eval_mutex_lock();
	expr = calloc(1, sizeof(struct expr));
	if (expr == NULL)
		goto error;

	expr->lineno = lineno;
	expr->colno = colno;

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
		cond->lineno = lineno;
		cond->colno = colno;

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
				if (((type == COND_CAPTURE_ONCE_BODY) ||
				     (type == COND_CAPTURE_ALL_BODY)
#ifdef GEOIP2
				     || (type == COND_CAPTURE_ONCE_BODY_GEO) ||
				     (type == COND_CAPTURE_ALL_BODY_GEO)
#endif
					    ) && cond->args[0].not) {
					yyerror("create_cond_4: 1st arg (capture arg) must not be negated");
					goto error;
				}

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
			if ((type == COND_CAPTURE_ONCE_BODY) ||
			    (type == COND_CAPTURE_ALL_BODY)) {
				/* nothing to prepare */
			}
#ifdef GEOIP2
			else if ((type == COND_CAPTURE_ONCE_BODY_GEO) ||
				 (type == COND_CAPTURE_ALL_BODY_GEO)) {
				if (build_geoip2_path(&cond->args[1]))
					goto error;
			}
#endif
			else {
				if (build_regex(&cond->args[1]))
					goto error;
			}
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
			    (type == COND_CAPTURE_MACRO)) {
				if (phase_of_envelope_member(c) != COND_NONE) {
					yyerror("create_cond_4: variable name \"%s\" is reserved", c);
					goto error;
				}
			} else
			if ((type == COND_COMPARE_HEADER) ||
			    (type == COND_COMPARE_CAPTURES)
#ifdef GEOIP2
			    || (type == COND_CAPTURE_ONCE_BODY_GEO) ||
			    (type == COND_CAPTURE_ALL_BODY_GEO)
#endif
				) {
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
				if (phase_of_envelope_member(d) != COND_NONE) {
					yyerror("create_cond_4: variable name \"%s\" is reserved", d);
					goto error;
				}
			} else
#endif
			{
				if (build_regex(&cond->args[3]))
					goto error;
				if (((type == COND_COMPARE_HEADER) ||
				     (type == COND_COMPARE_CAPTURES)) &&
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
	append_expr_to_list(elc, &cond->expr);
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
create_cond(struct ruleset *rs, cond_t type, const char *a, const char *b, int lineno, int colno)
{
	return create_cond_4(rs, type, a, b, NULL, NULL, lineno, colno);
}

struct expr *
create_capture(struct ruleset *rs, cond_t type, const char *a, const char *b, const char *c, const char *d, int lineno, int colno)
{
	struct expr *cap_expr = create_cond_4(rs, type, a, b, c, d, lineno, colno);
	if (cap_expr == NULL)
		return NULL;

	if (cap_expr->cond->expr && cap_expr->cond->expr->next) {
		yyerror("yyparse: duplicate capture expression");
		return NULL;
	}

	return cap_expr;
}

struct expr *
create_expr(struct ruleset *rs, int type, struct expr *a, struct expr *b, int lineno, int colno)
{
	struct expr *e = NULL;
	struct expr_list *ela = NULL, *elb = NULL;

	eval_mutex_lock();
	e = calloc(1, sizeof(struct expr));
	if (e == NULL)
		goto error;

	e->lineno = lineno;
	e->colno = colno;

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
		append_expr_to_list(ela, &a->expr);
	}
	if (b != NULL) {
		e->args[1] = b;
		elb->expr = e;
		append_expr_to_list(elb, &b->expr);
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
create_action(struct ruleset *rs, int type, const char *msgtxt, int lineno, int colno)
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
	a->colno = colno;
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
eval_cond_1(struct context *context, cond_t type,
    const char *a, const char *b)
{
	struct ruleset *rs = context->rs;
	int *res = context->res;

	struct cond_list *cl;

	int n_pushed = 0;
	int initial_captures_change_count = context->captures_change_count;

again:

	for (cl = rs->cond[type]; cl != NULL; cl = cl->next) {
		int r;
		if (res[cl->cond->idx] != VAL_UNDEF)
			continue;
		r = check_cond(context, cl->cond, a, b);
		if (r < 0)
			return (NULL);
		else if (!r) {
			push_cond_result(context, cl->cond, VAL_TRUE);
			++n_pushed;
		}
	}

	if (context->current_winning_action)
		return context->current_winning_action;

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
eval_cond(struct context *context, cond_t type,
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
eval_end(struct context *context, cond_t type)
{
	long long int start_at = now_usecs();
	struct ruleset *rs = context->rs;
	int *res = context->res;
	struct action *ret = &default_action;

	struct cond_list *cl;

	int n_pushed = 0;

	eval_mutex_lock();

	context->last_phase_done = type;

	for (cl = rs->cond[type]; cl != NULL; cl = cl->next) {
		if (res[cl->cond->idx] == VAL_UNDEF) {
			push_cond_result(context, cl->cond, VAL_FALSE);
			++n_pushed;
		}
	}

	if (type < COND_COMPARE_CAPTURES) {
		for (cl = rs->cond[COND_COMPARE_CAPTURES]; cl != NULL; cl = cl->next) {
			if ((cl->cond->end_phase == COND_NONE) || (cl->cond->end_phase > type))
				continue;
			if (res[cl->cond->idx] == VAL_UNDEF) {
				push_cond_result(context, cl->cond, VAL_FALSE);
				++n_pushed;
			}
		}
	}

	if (context->current_winning_action) {
		eval_mutex_unlock();
		if (debug)
			context->eval_time_cum += now_usecs() - start_at;
		return context->current_winning_action;
	}

	ret = eval_cond_1(context, COND_PHASEDONE, 0, 0);

	eval_mutex_unlock();
	if (debug)
		context->eval_time_cum += now_usecs() - start_at;
	return ret;
}

void
eval_clear(struct context *context, cond_t type)
{
	long long int start_at = now_usecs();
	struct ruleset *rs = context->rs;

	struct cond_list *cl;

	eval_mutex_lock();

#if 0
	for (; type < COND_MAX; ++type) {
		for (cl = rs->cond[type]; cl != NULL; cl = cl->next)
			push_cond_result(context, cl->cond, VAL_UNDEF);
#endif

	for (int type_i = COND_NONE + 1; type_i < COND_MAX; ++type_i) {
		for (cl = rs->cond[type]; cl != NULL; cl = cl->next) {
			if ((context->res_phase[cl->cond->idx] != COND_NONE) &&
			    (context->res_phase[cl->cond->idx] >= type))
				push_cond_result(context, cl->cond, VAL_UNDEF);
		}
	}

	context->current_winning_action = NULL;

	for (struct action_list *al = rs->action; al != NULL; al = al->next) {
		if (context->res[al->action->idx] != VAL_UNDEF) {
			msg(LOG_DEBUG, context,
			    "cleared action %s @L%d@%d %s@%s -> %s@%s",
			    lookup_action_name(al->action->type),
			    al->action->lineno,
			    al->action->colno,
			    lookup_res_name(context->res[al->action->idx]),
			    lookup_cond_name(context->res_phase[al->action->idx]),
			    lookup_res_name(VAL_UNDEF),
			    lookup_cond_name(context->current_phase));
			context->res[al->action->idx] = VAL_UNDEF;
		}
	}

	free_kv_bindings(context, &context->captures, type);

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
	new_kv->capture_phase = context->current_phase;
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

void free_kv_bindings(struct context *context, struct kv_binding **list_pp, cond_t keep_if_before) {
	struct kv_binding *list = *list_pp;
	while (list) {
		if (list->capture_phase < keep_if_before)
			list = list->next;
		else {
			struct kv_binding *prev = list->prev, *next = list->next;

			msg(LOG_DEBUG, context, "deleting KV \"%s\" = \"%.*s\"", list->key, (int)list->val_len, list->val);

			free(list);
			if (prev)
				prev->next = next;
			else
				*list_pp = next;
			if (next)
				next->prev = prev;
			list = next;
		}
	}
}

static int compare_values(const char *first, size_t first_len, struct cond_arg *first_cond,
			  const char *second, size_t second_len, struct cond_arg *second_cond) {

	int (*cmp_fn)(const char *s1, const char *s2, size_t n);
	if (first_cond->compare_case_insensitively || second_cond->compare_case_insensitively)
		cmp_fn = strncasecmp;
	else
		cmp_fn = (int (*)(const char *, const char *, size_t))memcmp;
	if (first_len == second_len)
		return cmp_fn(first, second, first_len);
	else if (second_len > first_len) {
		if (first_cond->compare_as_suffix) {
			if (! cmp_fn(first, second + (second_len - first_len), first_len))
				return 0;
		}
		if (first_cond->compare_as_dname_suffix) {
			if ((*(second + (second_len - first_len) - 1) == '.') &&
			    (! cmp_fn(first, second + (second_len - first_len), first_len)))
				return 0;
		}
		if (first_cond->compare_as_prefix) {
			if (! cmp_fn(first, second, first_len))
				return 0;
		}
		if (first_cond->compare_as_dname_prefix) {
			if ((second[first_len] == '.') &&
			    (! cmp_fn(first, second, first_len)))
				return 0;
		}
	} else {
		if (second_cond->compare_as_suffix) {
			if (! cmp_fn(second, first + (first_len - second_len), second_len))
				return 0;
		}
		if (second_cond->compare_as_dname_suffix) {
			if ((*(first + (first_len - second_len) - 1) == '.') &&
			    (! cmp_fn(second, first + (first_len - second_len), second_len)))
				return 0;
		}
		if (second_cond->compare_as_prefix) {
			if (! cmp_fn(second, first, second_len))
				return 0;
		}
		if (second_cond->compare_as_dname_prefix) {
			if ((first[second_len] == '.') &&
			    (! cmp_fn(second, first, second_len)))
				return 0;
		}
	}
	return 1;
}

static int get_envelope_member(struct context *context, const char *name, const char **value, size_t *value_len) {
	if (! name)
		return -EINVAL;

#define CHECK_ENVELOPE(checkname, membername) if (! strcmp(name,checkname)) { if (! *context->membername) { errno = EAGAIN; return -1; } *value = context->membername; *value_len = strnlen(context->membername, sizeof context->membername); return 0; }

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
#undef CHECK_ENVELOPE
}

static cond_t phase_of_envelope_member(const char *name) {
	if (! name)
		return COND_NONE;

#define CHECK_ENVELOPE(checkname, phase) if (! strcmp(name,checkname)) return (phase)

	CHECK_ENVELOPE("client_resolve", COND_CONNECT);
	CHECK_ENVELOPE("connect:hostname", COND_CONNECT);
	CHECK_ENVELOPE("connect:address", COND_CONNECT);
#ifdef GEOIP2
	if (! strcmp(name,"connect:geoip"))
		return COND_CONNECTGEO;
#endif
	CHECK_ENVELOPE("envfrom", COND_ENVFROM);
	CHECK_ENVELOPE("envrcpt", COND_ENVRCPT);
	CHECK_ENVELOPE("from", COND_HEADER);
	CHECK_ENVELOPE("helo", COND_HELO);
	if (! strncmp(name,"literal:",strlen("literal:")))
		return COND_STATIC;
	CHECK_ENVELOPE("message_id", COND_ENVFROM);
	CHECK_ENVELOPE("my_name", COND_CONNECT);
	CHECK_ENVELOPE("subject", COND_HEADER);
	CHECK_ENVELOPE("tls_status", COND_HELO);
	CHECK_ENVELOPE("to", COND_HEADER);

	return COND_NONE;
#undef CHECK_ENVELOPE
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
		if (r && r != REG_NOMATCH) {
			msg(LOG_WARNING, context, "regex error %d in %s@%d, for re \"%s\" at conf L%d@%d", r, __FILE__, __LINE__, c->args[0].src, c->lineno, c->colno);
			return -1;
		}
		else if ((r == REG_NOMATCH) != c->args[0].not)
			return 1;
		else
			return 0;
	}

	case COND_CAPTURE_ONCE_HEADER:
	case COND_CAPTURE_ALL_HEADER: {
		/* capture_{once,all}_header <header_LHS_match_re> <header_RHS_selector_re> <varname> */

		if ((! a) || (! b)) {
			msg(LOG_DEBUG, context, "null arg error in %s@%d, at conf L%d@%d", __FILE__, __LINE__, c->lineno, c->colno);
			return -1;
		}

		if (! c->args[0].empty) {
			int r = regexec(&c->args[0].re, a, 0, NULL, 0);
			if (r && r != REG_NOMATCH) {
				msg(LOG_WARNING, context, "regex error %d in %s@%d, for re \"%s\" at conf L%d@%d", r, __FILE__, __LINE__, c->args[0].src, c->lineno, c->colno);
				return -1;
			}
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
				if (r != REG_NOMATCH) {
					msg(LOG_WARNING, context, "regex error %d in %s@%d, for re \"%s\" at conf L%d@%d", r, __FILE__, __LINE__, c->args[1].src, c->lineno, c->colno);
					return -1;
				} else
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
		/* capture_{once,all}_header_geo <header_LHS_match_re> <header_RHS_selector_re> <geo_ip_path> <varname> */

		msg(LOG_DEBUG, context, "attempt to use unimplemented cond %s at conf L%d@%d", lookup_cond_name(c->type), c->lineno, c->colno);
		return -1;
	}
#endif

	case COND_CAPTURE_ONCE_BODY:
	case COND_CAPTURE_ALL_BODY: {
		/* capture_{once,all}_body <body_selector_re> <varname> */

		if (! a) {
			msg(LOG_DEBUG, context, "null arg error in %s@%d, at conf L%d@%d", __FILE__, __LINE__, c->lineno, c->colno);
			return -1;
		}

		ssize_t a_len_left = (ssize_t)strlen(a);

		if (c->args[0].empty) {
			insert_kv_binding(context, c->args[1].src, a, a_len_left, 0);
			return c->type == COND_CAPTURE_ALL_BODY; /* return false to arrange for calls on every header regardless of earlier match. */
		}

		const char *a_ptr = a;
		regmatch_t matches[8];
		struct kv_binding *point = 0;
		int n_inserted = 0;

		while (a_len_left > 0) {
			int r = regexec(&c->args[0].re, a_ptr, sizeof matches / sizeof matches[0], matches, (a_ptr != a) ? REG_NOTBOL : 0);
			if (r) {
				if (r != REG_NOMATCH) {
					msg(LOG_WARNING, context, "regex error %d in %s@%d, for re \"%s\" at conf L%d@%d", r, __FILE__, __LINE__, c->args[0].src, c->lineno, c->colno);
					return -1;
				} else
					break;
			}

			for (int i=1;;) {
				if (matches[i].rm_so != -1) {
					insert_kv_binding(context, c->args[1].src, a + matches[i].rm_so, matches[i].rm_eo - matches[i].rm_so, &point);
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

			if (! c->args[0].global)
			  break;

			a_len_left -= matches[0].rm_eo;
			a_ptr += matches[0].rm_eo;
		}

		if (c->type == COND_CAPTURE_ALL_BODY)
			return 1; /* return false to arrange for calls on every header regardless of earlier match. */
		else
			return (n_inserted > 0) ? 0 : 1;
	}

#ifdef GEOIP2
	case COND_CAPTURE_ONCE_BODY_GEO:
	case COND_CAPTURE_ALL_BODY_GEO: {
		/* capture_{once,all}_body_geo <body_selector_re> <geo_ip_path> <varname> */

		msg(LOG_DEBUG, context, "attempt to use unimplemented cond %s at conf L%d@%d", lookup_cond_name(c->type), c->lineno, c->colno);
		return -1;
	}
#endif

	case COND_CAPTURE_MACRO: {
		/* capture_macro <macro_LHS_match_re> <macro_RHS_selector_re> <varname> */

		if (! a) {
			msg(LOG_DEBUG, context, "null arg error in %s@%d, at conf L%d@%d", __FILE__, __LINE__, c->lineno, c->colno);
			return -1;
		}

		if (! b)
			return 1;

		if (! c->args[0].empty) {
			int r = regexec(&c->args[0].re, a, 0, NULL, 0);
			if (r && r != REG_NOMATCH) {
				msg(LOG_WARNING, context, "regex error %d in %s@%d, for re \"%s\" at conf L%d@%d", r, __FILE__, __LINE__, c->args[0].src, c->lineno, c->colno);
				return -1;
			}
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
				if (r != REG_NOMATCH) {
					msg(LOG_WARNING, context, "regex error %d in %s@%d, for re \"%s\" at conf L%d@%d", r, __FILE__, __LINE__, c->args[1].src, c->lineno, c->colno);
					return -1;
				} else
					break;
			}

			for (int i=1;;) {
				if (matches[i].rm_so != -1) {
					insert_kv_binding(context, c->args[2].src, b_ptr + matches[i].rm_so, matches[i].rm_eo - matches[i].rm_so, &point);
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

		msg(LOG_DEBUG, context, "attempt to use unimplemented cond %s at conf L%d@%d", lookup_cond_name(c->type), c->lineno, c->colno);
		return -1;
	}
#endif

	case COND_COMPARE_HEADER:
	case COND_COMPARE_CAPTURES: {
		/* compare_header <header_LHS_match_re> <header_RHS_selector_re> [!]<connect:host|connect:addr|helo|envfrom|envrcpt|var:name> [macro_RHS_selector_re] */

		/* compare_captures <connect:host|connect:addr|helo|envfrom|envrcpt|var:name> <value_selector_re1> <connect:host|connect:addr|helo|envfrom|envrcpt|var:name> <value_selector_re2> */

		/* (cond->args[1].src and [3].src can safely be null, though that's not currently used.) */

		/* test passes if any of vals for the first key equal any of the vals for the second. */

		/* if either selection RE has the O flag, the test is an ordered comparison of all captures for each left hand val with all captures for each right hand val,
		 * i.e. if {"a.b.c", "d.e.f"} on the left is selected with /[[:alnum:]]+/gO, and {"g-h-i", "a-b-c"} is selected with /[[:alnum:]]+/g on the right, they
		 * will succeed on the match of selections from "a.b.c" and "a-b-c".
		 */

		/*
		 * note this is quite an elaborate nested loop proposition.  not only
		 * is there iteration among all members of each set, but also, for
		 * each member there is iteration through captures, not
		 * just through captures via a multi-capture RE, but for global-tagged
		 * REs, through all captures tiling the RE across each member.  the
		 * cumulative iterator depth is 6.
		 *
		 * with the 'O' flag, an alternate codepath is followed, using gotos
		 * to collapse levels 3-6 into a single loop with the two operands
		 * stepping forward in sync, so that all selections can be compared
		 * in order.
		 *
		 * Complexity Scores
		 * Score | ln-ct | nc-lns| file-name(line): proc-name
		 * 2840     899     701   eval.c(801): check_cond
		 */

		const struct kv_binding *first_operand_i, *second_operand_i_first;
		const char *first_operand_preselection;
		size_t first_operand_preselection_len = 0;

		if (c->type == COND_COMPARE_HEADER) {
			if ((! a) || (! b)) {
				msg(LOG_DEBUG, context, "null arg error in %s@%d, at conf L%d@%d", __FILE__, __LINE__, c->lineno, c->colno);
				return -1;
			}
			if (! c->args[0].empty) {
				int r = regexec(&c->args[0].re, a, 0, NULL, 0);
				if (r && r != REG_NOMATCH) {
					msg(LOG_WARNING, context, "regex error %d in %s@%d, for re \"%s\" at conf L%d@%d", r, __FILE__, __LINE__, c->args[0].src, c->lineno, c->colno);
					return -1;
				}
				if ((r == REG_NOMATCH) != c->args[0].not)
					return 1;
			}
			first_operand_preselection = b;
			first_operand_i = 0;
		} else {
			first_operand_preselection = get_kv_binding_first(context, c->args[0].src, &first_operand_i);

			if (! first_operand_preselection) {
				if (get_envelope_member(context, c->args[0].src, &first_operand_preselection, &first_operand_preselection_len) < 0)
					return 1;
				first_operand_i = 0;
			}
		}

		const char *second_operand_preselection_first = get_kv_binding_first(context, c->args[2].src, &second_operand_i_first);
		size_t second_operand_preselection_len = 0;
		if (! second_operand_preselection_first) {
		  if (get_envelope_member(context, c->args[2].src, &second_operand_preselection_first, &second_operand_preselection_len) < 0)
		    return 1;
		  second_operand_i_first = 0;
		}

		for (;
		     first_operand_preselection;
		     first_operand_preselection = first_operand_i ? get_kv_binding_next(&first_operand_i) : 0)
/* 1 */		{
		  const char *first_operand;
		  size_t first_operand_len = 0;
		  ssize_t first_operand_len_left = first_operand_preselection_len ? (ssize_t)first_operand_preselection_len : (ssize_t)strlen(first_operand_preselection);
		  const char *first_operand_ptr = first_operand_preselection, *last_used_first_operand_ptr = first_operand_preselection;

		  const char *second_operand_preselection = second_operand_preselection_first;
		  const struct kv_binding *second_operand_i = second_operand_i_first;

		  for (;
		       second_operand_preselection;
		       second_operand_preselection = second_operand_i ? get_kv_binding_next(&second_operand_i) : 0)
/* 2 */		  {
		    const char *second_operand;
		    size_t second_operand_len = 0;
		    ssize_t second_operand_len_left =
		      second_operand_preselection_len ?
		      (ssize_t)second_operand_preselection_len :
		      (ssize_t)strlen(second_operand_preselection);
		    const char *second_operand_ptr = second_operand_preselection, *last_used_second_operand_ptr = second_operand_preselection;

/* 3 */
		    if (c->args[1].compare_ordered_match_all_selections || c->args[3].compare_ordered_match_all_selections) {

		      regmatch_t first_operand_matches[8];
		      int first_operand_matches_i = 0;
		      int first_operand_matches_left = 0;
		      int first_operand_n_captures = 0;

		      regmatch_t second_operand_matches[8];
		      int second_operand_matches_i = 0;
		      int second_operand_matches_left = 0;
		      int second_operand_n_captures = 0;

		      int n_matches_overall = 0, mismatch_p = 0;

		      do
/* 3-6 'O' */
		      {
			if ((! first_operand_len_left) && (! first_operand_matches_left))
			  first_operand = 0;
			else if (c->args[1].empty || (! c->args[1].src)) {
			  first_operand = first_operand_preselection;
			  first_operand_len = first_operand_len_left;
			  first_operand_matches_left = 0;
			  first_operand_len_left = 0;
			} else {
			first_next_O_outer_capture:
			  first_operand = 0;
			  if ((first_operand_len_left > 0) && (first_operand_matches_left <= 0))  {
			    last_used_first_operand_ptr = first_operand_ptr;
			    int r = regexec(&c->args[1].re,
					    first_operand_ptr,
					    sizeof first_operand_matches / sizeof first_operand_matches[0],
					    first_operand_matches,
					    (first_operand_ptr != first_operand_preselection) ? REG_NOTBOL : 0);
			    if (r || (first_operand_matches[0].rm_so < 0)) {
			      if (r != REG_NOMATCH) {
				msg(LOG_WARNING, context, "regex error %d in %s@%d, for re \"%s\" at conf L%d@%d", r, __FILE__, __LINE__, c->args[1].src, c->lineno, c->colno);
				return -1;
			      } else {
				first_operand_len_left = 0;
				goto get_second_O_operand;
			      }
			    }

			    first_operand_matches_left = (int)(sizeof first_operand_matches / sizeof first_operand_matches[0]) + 1; /* +1 for the fallback whole-matched-span */
			    first_operand_matches_i = 0;
			    first_operand_n_captures = 0;
			    if (c->args[1].global) {
			      first_operand_len_left -= first_operand_matches[0].rm_eo;
			      first_operand_ptr += first_operand_matches[0].rm_eo;
			    } else
			      first_operand_len_left = 0;
			  }

			first_next_O_inner_capture:
			  if (first_operand_matches_left > 0) {

			    --first_operand_matches_left;
			    ++first_operand_matches_i;

			    /* fall back to whole-matched-span if necessary. */
			    if (first_operand_matches_i == (int)(sizeof first_operand_matches / sizeof first_operand_matches[0])) {
			      if (! first_operand_n_captures)
				first_operand_matches_i = 0;
			      else {
				first_operand_matches_left = 0;
				goto first_next_O_outer_capture;
			      }
			    }

			    if (first_operand_matches[first_operand_matches_i].rm_so < 0)
			      goto first_next_O_inner_capture;

			    ++first_operand_n_captures;

			    first_operand = last_used_first_operand_ptr + first_operand_matches[first_operand_matches_i].rm_so;
			    first_operand_len = first_operand_matches[first_operand_matches_i].rm_eo - first_operand_matches[first_operand_matches_i].rm_so;

			  } else if (first_operand_len_left > 0)
			    goto first_next_O_outer_capture;
			  /* else leave first_operand null. */
			}

		      get_second_O_operand:

			if ((! second_operand_len_left) && (! second_operand_matches_left))
			  second_operand = 0;
			else if (c->args[3].empty || (! c->args[3].src)) {
			  second_operand = second_operand_preselection;
			  second_operand_len = second_operand_len_left;
			  second_operand_matches_left = 0;
			  second_operand_len_left = 0;
			} else {
			second_next_O_outer_capture:
			  second_operand = 0;
			  if ((second_operand_len_left > 0) && (second_operand_matches_left <= 0))  {
			    last_used_second_operand_ptr = second_operand_ptr;
			    int r = regexec(&c->args[3].re,
					    second_operand_ptr,
					    sizeof second_operand_matches / sizeof second_operand_matches[0],
					    second_operand_matches,
					    (second_operand_ptr != second_operand_preselection) ? REG_NOTBOL : 0);
			    if (r || (second_operand_matches[0].rm_eo < 0)) {
			      if (r != REG_NOMATCH) {
				msg(LOG_WARNING, context, "regex error %d in %s@%d, for re \"%s\" at conf L%d@%d", r, __FILE__, __LINE__, c->args[3].src, c->lineno, c->colno);
				return -1;
			      } else {
				second_operand_len_left = 0;
				goto compare_O_operands;
			      }
			    }

			    second_operand_matches_left = (int)(sizeof second_operand_matches / sizeof second_operand_matches[0]) + 1; /* +1 for the fallback whole-matched-span */
			    second_operand_matches_i = 0;
			    second_operand_n_captures = 0;
			    if (c->args[3].global) {
			      second_operand_len_left -= second_operand_matches[0].rm_eo;
			      second_operand_ptr += second_operand_matches[0].rm_eo;
			    } else
			      second_operand_len_left = 0;
			  }

			second_next_O_inner_capture:
			  if (second_operand_matches_left > 0) {

			    --second_operand_matches_left;
			    ++second_operand_matches_i;

			    /* fall back to whole-matched-span if necessary. */
			    if (second_operand_matches_i == (int)(sizeof second_operand_matches / sizeof second_operand_matches[0])) {
			      if (! second_operand_n_captures)
				second_operand_matches_i = 0;
			      else {
				second_operand_matches_left = 0;
				goto second_next_O_outer_capture;
			      }
			    }

			    if (second_operand_matches[second_operand_matches_i].rm_so < 0)
			      goto second_next_O_inner_capture;

			    ++second_operand_n_captures;

			    second_operand = last_used_second_operand_ptr + second_operand_matches[second_operand_matches_i].rm_so;
			    second_operand_len = second_operand_matches[second_operand_matches_i].rm_eo - second_operand_matches[second_operand_matches_i].rm_so;

			  } else if (second_operand_len_left > 0)
			    goto second_next_O_outer_capture;
			  /* else leave second_operand null. */
			}

		      compare_O_operands:

			if ((! first_operand) && (! second_operand))
			  ;
			else if ((! first_operand) || (! second_operand)) {
			  mismatch_p = 1;
			  break;
			} else if (compare_values(first_operand, first_operand_len, &c->args[1], second_operand, second_operand_len, &c->args[3]) != 0) {
			  mismatch_p = 1;
			  break;
			}
			++n_matches_overall;
		      } /* end 3 O */
		      while (((first_operand_len_left > 0) ||
			      (first_operand_matches_left > 0)) &&
			     ((second_operand_len_left > 0) ||
			      (second_operand_matches_left > 0)));

		      if ((n_matches_overall > 0) &&
			  (! mismatch_p) &&
			  (first_operand_len_left == 0) &&
			  (first_operand_matches_left == 0) &&
			  (second_operand_len_left == 0) &&
			  (second_operand_matches_left == 0))
			return 0;

/* end 3-6 'O' */

		    } else /* any-matches-any */ {

		      while (first_operand_len_left > 0)
/* 3 !'O' */
		      {
			regmatch_t first_operand_matches[8];
			int first_operand_matches_i = 0;
			int first_operand_matches_left = 0;
			int first_operand_n_captures = 0;

			do
/* 4 */
			{

			  if (c->args[1].empty || (! c->args[1].src)) {

			    first_operand = first_operand_preselection;
			    first_operand_len = first_operand_len_left;
			    first_operand_matches_left = 1;
			    first_operand_len_left = 0;

			  } else {

			    if (first_operand_matches_i == 0) {
			      last_used_first_operand_ptr = first_operand_ptr;
			      int r = regexec(&c->args[1].re,
					      first_operand_ptr,
					      sizeof first_operand_matches / sizeof first_operand_matches[0],
					      first_operand_matches,
					      (first_operand_ptr != first_operand_preselection) ? REG_NOTBOL : 0);
			      if (r) {
				if (r != REG_NOMATCH) {
				  msg(LOG_WARNING, context, "regex error %d in %s@%d, for re \"%s\" at conf L%d@%d", r, __FILE__, __LINE__, c->args[1].src, c->lineno, c->colno);
				  return -1;
				} else {
				  first_operand_len_left = 0;
				  continue;
				}
			      }


			      if (c->args[1].global) {
				first_operand_len_left -= first_operand_matches[0].rm_eo;
				first_operand_ptr += first_operand_matches[0].rm_eo;
			      } else
				first_operand_len_left = 0;
			      first_operand_matches_left = (int)(sizeof first_operand_matches / sizeof first_operand_matches[0]) + 1; /* +1 for the fallback whole-matched-span */
			    }

			    ++first_operand_matches_i;

			    /* fall back to whole-matched-span if necessary. */
			    if (first_operand_matches_i == (int)(sizeof first_operand_matches / sizeof first_operand_matches[0])) {
			      if (! first_operand_n_captures)
				first_operand_matches_i = 0;
			      else
				break;
			    }

			    if (first_operand_matches[first_operand_matches_i].rm_so == -1)
			      continue;

			    ++first_operand_n_captures;

			    first_operand = last_used_first_operand_ptr + first_operand_matches[first_operand_matches_i].rm_so;
			    first_operand_len = first_operand_matches[first_operand_matches_i].rm_eo - first_operand_matches[first_operand_matches_i].rm_so;

			  }

			  while (second_operand_len_left > 0)
/* 5 */
			  {
			    regmatch_t second_operand_matches[8];
			    int second_operand_matches_i = 0;
			    int second_operand_matches_left = 0;
			    int second_operand_n_captures = 0;

			    do
/* 6 */
			    {

			      if (c->args[3].empty || (! c->args[3].src)) {

				second_operand = second_operand_preselection;
				second_operand_len = second_operand_len_left;
				second_operand_matches_left = 1;
				second_operand_len_left = 0;

			      } else {

				if (second_operand_matches_i == 0) {
				  last_used_second_operand_ptr = second_operand_ptr;
				  int r = regexec(&c->args[3].re,
						  second_operand_ptr,
						  sizeof second_operand_matches / sizeof second_operand_matches[0],
						  second_operand_matches,
						  (second_operand_ptr != second_operand_preselection) ? REG_NOTBOL : 0);
				  if (r) {
				    if (r != REG_NOMATCH) {
				      msg(LOG_WARNING, context, "regex error %d in %s@%d, for re \"%s\" at conf L%d@%d", r, __FILE__, __LINE__, c->args[3].src, c->lineno, c->colno);
				      return -1;
				    } else {
				      second_operand_len_left = 0;
				      continue;
				    }
				  }

				  if (c->args[3].global) {
				    second_operand_len_left -= second_operand_matches[0].rm_eo;
				    second_operand_ptr += second_operand_matches[0].rm_eo;
				  } else
				    second_operand_len_left = 0;
				  second_operand_matches_left = (int)(sizeof second_operand_matches / sizeof second_operand_matches[0]) + 1; /* +1 for the fallback whole-matched-span */
				}

				++second_operand_matches_i;

				/* fall back to whole-matched-span if necessary. */
				if (second_operand_matches_i == (int)(sizeof second_operand_matches / sizeof second_operand_matches[0])) {
				  if (! second_operand_n_captures)
				    second_operand_matches_i = 0;
				  else
				    break;
				}

				if (second_operand_matches[second_operand_matches_i].rm_so == -1)
				  continue;

				++second_operand_n_captures;

				second_operand = last_used_second_operand_ptr + second_operand_matches[second_operand_matches_i].rm_so;
				second_operand_len = second_operand_matches[second_operand_matches_i].rm_eo - second_operand_matches[second_operand_matches_i].rm_so;

			      }

			      if (compare_values(first_operand, first_operand_len, &c->args[1], second_operand, second_operand_len, &c->args[3]) == 0)
				return 0;

/* end 6 */
			    } while (--second_operand_matches_left > 0);

/* end 5 */
			  }

/* end 4 */
			} while (--first_operand_matches_left > 0);

/* end 3 !'O' */
		      }

/* end 3 */
		    }

/* end 2 */
		  }

/* end 1 */
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

		if (! b) {
			msg(LOG_DEBUG, context, "null arg error in %s@%d, at conf L%d@%d", __FILE__, __LINE__, c->lineno, c->colno);
			return -1;
		}
		if (c->args[0].empty) {
			if (a) {
				if (c->args[0].not)
					return 1;
			} else {
				if (! c->args[0].not)
					return 1;
			}
		} else {
			if (a == NULL) {
				msg(LOG_DEBUG, context, "null arg error in %s@%d, at conf L%d@%d", __FILE__, __LINE__, c->lineno, c->colno);
				return -1;
			}
		}

		if (! c->args[0].empty) {
			int r = regexec(&c->args[0].re, a, 0, NULL, 0);
			if (r && r != REG_NOMATCH) {
				msg(LOG_WARNING, context, "regex error %d in %s@%d, for re \"%s\" at conf L%d@%d", r, __FILE__, __LINE__, c->args[0].src, c->lineno, c->colno);
				return -1;
			}
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
					if (r != REG_NOMATCH) {
						msg(LOG_WARNING, context, "regex error %d in %s@%d, for re \"%s\" at conf L%d@%d", r, __FILE__, __LINE__, c->args[1].src, c->lineno, c->colno);
						return -1;
					} else
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
			if (d == NULL) {
				if ((c->type == COND_MACRO) && (i == 1))
					return 1; /* a null macro RHS is just a normal mismatch. */
				else {
					msg(LOG_DEBUG, context, "null arg error in %s@%d, at conf L%d@%d (%s)", __FILE__, __LINE__, c->lineno, c->colno, lookup_cond_name(c->type));
					return -1;
				}
			}
			r = regexec(&c->args[i].re, d, 0, NULL, 0);
			if (r && r != REG_NOMATCH) {
				msg(LOG_WARNING, context, "regex error %d in %s@%d, for re \"%s\" at conf L%d@%d", r, __FILE__, __LINE__, c->args[i].src, c->lineno, c->colno);
				return -1;
			}
			if ((r == REG_NOMATCH) != c->args[i].not)
				return 1;
		}
		return 0;
	}

	msg(LOG_DEBUG, context, "flow error -- check_cond fell through to end checking %s cond at conf L%d@%d", lookup_cond_name(c->type), c->lineno, c->colno);
	return 1;
}

static void
push_expr_result(struct context *context, struct expr *e, int val)
{
	struct expr_list *el;
	int *res = context->res;

	if (res[e->idx] == val)
		return;
	res[e->idx] = val;
	if (e->action != NULL && val == VAL_TRUE) {
		res[e->action->idx] = val;
		if ((context->current_winning_action == NULL) || (e->action->idx < context->current_winning_action->idx))
			context->current_winning_action = e->action;
		context->res_phase[e->action->idx] = context->current_phase;

		msg(LOG_DEBUG, context,
		    "asserted action %s, idx %d, config L%d@%d, message phase %s",
		    lookup_action_name(e->action->type),
		    e->action->idx,
		    e->action->lineno,
		    e->action->colno,
		    lookup_cond_name(context->current_phase));
	}
	for (el = e->expr; el != NULL; el = el->next) {
		struct expr *p = el->expr;

		switch (p->type) {
		case EXPR_AND:
			if (res[p->args[0]->idx] == VAL_TRUE &&
			    res[p->args[1]->idx] == VAL_TRUE)
				push_expr_result(context, p, VAL_TRUE);
			else if (res[p->args[0]->idx] == VAL_FALSE ||
			    res[p->args[1]->idx] == VAL_FALSE)
				push_expr_result(context, p, VAL_FALSE);
			else
				push_expr_result(context, p, VAL_UNDEF);
			break;
		case EXPR_OR:
			if (res[p->args[0]->idx] == VAL_TRUE ||
			    res[p->args[1]->idx] == VAL_TRUE)
				push_expr_result(context, p, VAL_TRUE);
			else if (res[p->args[0]->idx] == VAL_FALSE &&
			    res[p->args[1]->idx] == VAL_FALSE)
				push_expr_result(context, p, VAL_FALSE);
			else
				push_expr_result(context, p, VAL_UNDEF);
			break;
		case EXPR_NOT:
			if (val == VAL_TRUE)
				push_expr_result(context, p, VAL_FALSE);
			else if (val == VAL_FALSE)
				push_expr_result(context, p, VAL_TRUE);
			else
				push_expr_result(context, p, VAL_UNDEF);
			break;
		default:
			break;
		}
	}
}

static void
push_cond_result(struct context *context, struct cond *c, int val)
{
	struct expr_list *el;

	if (context->res[c->idx] == val)
		return;

	msg(LOG_DEBUG, context,
	    "pushed result %s \"%s\"... @L%d@%d %s@%s -> %s@%s",
	    lookup_cond_name(c->type),
	    c->args[0].src,
	    c->lineno,
	    c->colno,
	    lookup_res_name(context->res[c->idx]),
	    lookup_cond_name(context->res_phase[c->idx]),
	    lookup_res_name(val),
	    lookup_cond_name(context->current_phase));

	context->res[c->idx] = val;
	context->res_phase[c->idx] = context->current_phase;

	for (el = c->expr; el != NULL; el = el->next) {
		struct expr *e = el->expr;

		if (e->type != EXPR_COND)
			continue;
		push_expr_result(context, e, val);
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
		case 'I':
			a->compare_case_insensitively = 1;
			break;
		case 'O':
			a->compare_ordered_match_all_selections = 1;
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
	if (! geoip2_db_path) {
		yyerror("create_cond_4: geoip condition, but no geoip database path.\n");
		return 1;
	}

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

void
unreverse_ruleset_cond_list(struct ruleset *rs)
{
	int i;

	eval_mutex_lock();
	if (rs == NULL || rs->refcnt) {
		eval_mutex_unlock();
		return;
	}
	for (i = 0; i < COND_MAX; ++i) {
		struct cond_list *cl = rs->cond[i], *clp = NULL;

		while (cl != NULL) {
			struct cond_list *cln = cl->next;

			cl->next = clp;
			clp = cl;
			if (cln == NULL)
				rs->cond[i] = cl;
			cl = cln;
		}
	}

	/* actions were already tail-inserted. */

	eval_mutex_unlock();
}

static cond_t
end_phase_of_var(struct ruleset *rs, const char *var) {
	cond_t ret = COND_NONE;
	for (struct cond_list *cl = rs->cond[COND_CAPTURE_MACRO];
	     cl;
	     cl = cl->next) {
		if (! strcmp(cl->cond->args[2].src, var)) {
			cond_t macro_phase = get_phase_of_macro_by_re(&cl->cond->args[0].re);
			if (ret < macro_phase)
				ret = macro_phase;
		}
	}

	if (ret < COND_BODY) {
		for (struct cond_list *cl = rs->cond[COND_CAPTURE_ONCE_BODY];
		     cl;
		     cl = cl->next) {
			if (! strcmp(cl->cond->args[2].src, var)) {
				ret = COND_BODY;
				break;
			}
		}
	}

	if (ret < COND_BODY) {
		for (struct cond_list *cl = rs->cond[COND_CAPTURE_ALL_BODY];
		     cl;
		     cl = cl->next) {
			if (! strcmp(cl->cond->args[2].src, var)) {
				ret = COND_BODY;
				break;
			}
		}
	}

	if (ret < COND_HEADER) {
		for (struct cond_list *cl = rs->cond[COND_CAPTURE_ONCE_HEADER];
		     cl;
		     cl = cl->next) {
			if (! strcmp(cl->cond->args[2].src, var)) {
				ret = COND_HEADER;
				break;
			}
		}
	}

	if (ret < COND_HEADER) {
		for (struct cond_list *cl = rs->cond[COND_CAPTURE_ALL_HEADER];
		     cl;
		     cl = cl->next) {
			if (! strcmp(cl->cond->args[2].src, var)) {
				ret = COND_HEADER;
				break;
			}
		}
	}

	if (ret == COND_NONE)
		return phase_of_envelope_member(var);
	else
		return ret;
}

int
calculate_end_phases_of_compare_captures(struct ruleset *rs, char *err_string, size_t err_string_len)
{
	struct cond_list *cl;

	eval_mutex_lock();
	if (rs == NULL || rs->refcnt) {
		eval_mutex_unlock();
		return 0;
	}

	for (cl = rs->cond[COND_COMPARE_CAPTURES]; cl != NULL; cl = cl->next) {
		cond_t end_phase_left = end_phase_of_var(rs, cl->cond->args[0].src);
		cond_t end_phase_right = end_phase_of_var(rs, cl->cond->args[2].src);

		if (end_phase_left == COND_NONE) {
			if (err_string && (err_string_len > 0))
				snprintf(err_string, err_string_len, "unresolvable variable reference \"%s\" at L%d C%d.", cl->cond->args[0].src, cl->cond->lineno, cl->cond->colno);
			return -1;
		}

		if (end_phase_right == COND_NONE) {
			if (err_string && (err_string_len > 0))
				snprintf(err_string, err_string_len, "unresolvable variable reference \"%s\" at L%d C%d.", cl->cond->args[2].src, cl->cond->lineno, cl->cond->colno);
			return -1;
		}

		if (end_phase_left > end_phase_right)
			cl->cond->end_phase = end_phase_left;
		else
			cl->cond->end_phase = end_phase_right;

	}

	return 0;
}

unsigned int compute_cond_hash(struct ruleset *rs) {
	unsigned int cond_hash = 0;
	for (int cl_i = 0; cl_i < COND_MAX; ++cl_i) {
		for (struct cond_list *cl = rs->cond[cl_i];
		     cl;
		     cl = cl->next) {
		/* barrel roll, but always by at least one. */
#define BROLL(x, b) x = (((b) & 0x1f) ? (((x) << ((b) & 0x1f)) | ((x) >> ((sizeof(x) * 8U) - ((b) & 0x1f)))) : (((x) << 1U) | ((x) >> ((sizeof(x) * 8U) - 1U))))
			cond_hash ^= (unsigned int)cl->cond->type;
			BROLL(cond_hash, cond_hash);
			/* note, don't stir in line/column numbers -- -R reports them relative to the
			 * newly supplied config file, and if the cond hash matches, then by definition,
			 * file layout changes aren't semantically significant for purposes of -R.
			 */
			for (unsigned int arg_i = 0; arg_i < sizeof cl->cond->args / sizeof cl->cond->args[0]; ++arg_i) {
				if (cl->cond->args[arg_i].src) {
					for (const char *cp = cl->cond->args[arg_i].src; *cp; ++cp) {
						cond_hash ^= (unsigned int)*cp;
						BROLL(cond_hash, cond_hash);
					}
				}
				BROLL(cond_hash, cond_hash); /* delineate the arguments. */
			}
		}
	}
	cond_hash ^= (cond_hash >> 30U); /* just in case, stir in the top 2 bits
					  * to the bottom 2, since base64 will
					  * discard the top 2.
					  */
	return cond_hash;
}

const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int build_res_report(struct context *context) {
	if (context->res_report)
		return 0;
	context->res_report = (char *)malloc(context->rs->maxidx + 6);
	if (! context->res_report)
		return -1;
	else {
		char *crbp = context->res_report;
		int thischar = 0;
		int thisbit = 0;

		*crbp++ = BASE64_CHAR(context->rs->cond_hash);
		*crbp++ = BASE64_CHAR(context->rs->cond_hash >> 6);
		*crbp++ = BASE64_CHAR(context->rs->cond_hash >> 12);
		*crbp++ = BASE64_CHAR(context->rs->cond_hash >> 18);
		*crbp++ = BASE64_CHAR(context->rs->cond_hash >> 24);

		for (int cl_i = 0; cl_i < COND_MAX; ++cl_i) {
			for (struct cond_list *cl = context->rs->cond[cl_i];
			     cl;
			     cl = cl->next) {
				if (context->res[cl->cond->idx] == VAL_TRUE)
					thischar |= 1 << thisbit;
				if (++thisbit == 6) {
					*crbp++ = base64_chars[thischar];
					thischar = 0;
					thisbit = 0;
				}
			}
		}
		if (thisbit > 0)
			*crbp++ = base64_chars[thischar];
		*crbp = 0;
		return 0;
	}
}

int res_decode(const struct ruleset *rs, const char *res_to_decode, int decode_all_flag) {
	int cond_n = 0;
	int res_len = strlen(res_to_decode);

	if (res_len < 5) {
		printf("supplied res is too short.\n");
		return -1;
	}

	if ((*res_to_decode++ != BASE64_CHAR(rs->cond_hash)) ||
	    (*res_to_decode++ != BASE64_CHAR(rs->cond_hash >> 6)) ||
	    (*res_to_decode++ != BASE64_CHAR(rs->cond_hash >> 12)) ||
	    (*res_to_decode++ != BASE64_CHAR(rs->cond_hash >> 18)) ||
	    (*res_to_decode++ != BASE64_CHAR(rs->cond_hash >> 24))) {
		printf("supplied res does not match loaded config.\n");
		return -1;
	}

	res_len -= 5;

	for (int cl_i = 0; cl_i < COND_MAX; ++cl_i) {
		for (const struct cond_list *cl = rs->cond[cl_i];
		     cl;
		     cl = cl->next) {
			int cond_byte_offset = cond_n / 6;
			int cond_bit_offset = cond_n % 6;
			if (cond_byte_offset >= res_len) {
				printf("supplied res is too short for loaded config.\n");
				return -1;
			}
			int decoded = res_to_decode[cond_byte_offset];
			if ((decoded >= 'A') && (decoded <= 'Z'))
				decoded -= 'A';
			else if ((decoded >= 'a') && (decoded <= 'z'))
				decoded -= ('a' - 26);
			else if ((decoded >= '0') && (decoded <= '9'))
				decoded -= ('0' - 52);
			else if (decoded == '+')
				decoded = 62;
			else if (decoded == '/')
				decoded = 63;
			else {
				printf("supplied res has non-base64 char #%d.\n", decoded);
				return -1;
			}
			if (decode_all_flag || (decoded & (1 << cond_bit_offset))) {
				printf("R=%d L%d C%d %s", decoded & (1 << cond_bit_offset) ? 1 : 0, cl->cond->lineno, cl->cond->colno, lookup_cond_name(cl->cond->type));
				if (cl->cond->args[0].src)
					printf(" %s", cl->cond->args[0].src);
				if (cl->cond->args[1].src)
					printf(" %s", cl->cond->args[1].src);
				if (cl->cond->args[2].src)
					printf(" %s", cl->cond->args[2].src);
				if (cl->cond->args[3].src)
					printf(" %s", cl->cond->args[3].src);
				putchar('\n');
			}
			++cond_n;
		}
	}
	if ((cond_n + 5) / 6 != res_len) {
		printf("supplied res length is %d, but loaded config produces res length %d.\n", res_len, (cond_n + 5) / 6);
		return -1;
	} else
		return 0;
}
