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

static const char rcsid[] = "$Id: eval.c,v 1.1.1.1 2007/01/11 15:49:52 dhartmei Exp $";

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

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

static pthread_mutex_t	 eval_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct action	 default_action;

int
eval_init(int type)
{
	memset(&default_action, 0, sizeof(default_action));
	default_action.type = type;
	return 0;
}

static void
eval_mutex_lock(void)
{
	int rv = pthread_mutex_lock(&eval_mutex);
	if (rv)
		die_with_errno(rv,"pthread_mutex_lock");
}

static void
eval_mutex_unlock(void)
{
	int rv = pthread_mutex_unlock(&eval_mutex);
	if (rv)
		die_with_errno(rv,"pthread_mutex_unlock");
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

struct expr *
create_cond(struct ruleset *rs, int type, const char *a, const char *b)
{
	struct cond *c = NULL;
	struct cond_list *cl = NULL;
	struct expr *e = NULL;
	struct expr_list *elc = NULL;

	eval_mutex_lock();
	e = calloc(1, sizeof(struct expr));
	if (e == NULL)
		goto error;
	elc = calloc(1, sizeof(struct expr_list));
	if (elc == NULL)
		goto error;

	for (cl = rs->cond[type]; cl != NULL; cl = cl->next) {
		if ((cl->cond->args[0].src == NULL) != (a == NULL) ||
		    (cl->cond->args[1].src == NULL) != (b == NULL) ||
		    (a != NULL && strcmp(a, cl->cond->args[0].src)) ||
		    (b != NULL && strcmp(b, cl->cond->args[1].src)))
			continue;
		break;
	}
	if (cl != NULL)
		c = cl->cond;
	else {
		cl = calloc(1, sizeof(struct cond_list));
		if (cl == NULL)
			goto error;
		c = calloc(1, sizeof(struct cond));
		if (c == NULL)
			goto error;

		if (a != NULL) {
			c->args[0].src = strdup(a);
			if (c->args[0].src == NULL)
				goto error;
#ifdef GEOIP2
			c->type = type;
			if (type == COND_CONNECTGEO) {
				if (build_geoip2_path(&c->args[0]))
					goto error;
			} else {
#endif
				if (build_regex(&c->args[0]))
					goto error;
#ifdef GEOIP2
			}
#endif
		}
		if (b != NULL) {
			c->args[1].src = strdup(b);
			if (c->args[1].src == NULL)
				goto error;
			if (build_regex(&c->args[1]))
				goto error;
		}
		c->idx = rs->maxidx++;
		cl->cond = c;
		cl->next = rs->cond[type];
		rs->cond[type] = cl;
	}

	e->type = EXPR_COND;
	e->cond = c;
	e->idx = rs->maxidx++;
	elc->expr = e;
	elc->next = c->expr;
	c->expr = elc;
	eval_mutex_unlock();
	return (e);

error:
	if (elc != NULL)
		free(elc);
	if (e != NULL)
		free(e);
	if (cl != NULL)
		free(cl);
	if (c != NULL) {
		if (!c->args[1].empty)
			regfree(&c->args[1].re);
		if (c->args[1].src != NULL)
			free(c->args[1].src);
		if (!c->args[0].empty)
			regfree(&c->args[0].re);
		if (c->args[0].src != NULL)
			free(c->args[0].src);
		free(c);
	}
	eval_mutex_unlock();
	return (NULL);
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
	for (al = rs->action; al != NULL; al = al->next)
		if (res[al->action->idx] == VAL_TRUE)
			return (al->action);
	return (NULL);
}

struct action *
eval_cond(struct context *context, int type,
    const char *a, const char *b)
{
	struct action *ret;
	eval_mutex_lock();
	ret = eval_cond_1(context,type,a,b);
	eval_mutex_unlock();
	return ret;
}

struct action *
eval_end(struct context *context, int type, int max)
{
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
	for (al = rs->action; al != NULL; al = al->next)
		if (res[al->action->idx] == VAL_TRUE) {
			eval_mutex_unlock();
			return (al->action);
		}
	for (type = max; type < COND_MAX; ++type) {
		if (type == COND_PHASEDONE)
			continue;
		for (cl = rs->cond[type]; cl != NULL; cl = cl->next)
			if (res[cl->cond->idx] == VAL_UNDEF)
				break;
	}

	ret = eval_cond_1(context, COND_PHASEDONE, 0, 0);

	eval_mutex_unlock();
	return ret;
}

void
eval_clear(struct context *context, int type)
{
	struct ruleset *rs = context->rs;
	int *res = context->res;

	struct cond_list *cl;

	eval_mutex_lock();
	for (; type < COND_MAX; ++type)
		for (cl = rs->cond[type]; cl != NULL; cl = cl->next)
			push_cond_result(cl->cond, VAL_UNDEF, res);
	eval_mutex_unlock();
}

static int
check_cond(struct context *context, struct cond *c, const char *a, const char *b)
{
#ifdef GEOIP2
	/* if this is a GeoIP rule, the first arg is the path, not a regexp, and the second arg is always null, to be replaced with the GeoIP leaf. */

	if (c->type == COND_CONNECTGEO) {
		if ((! c->args[0].geoip2_path[0]) || (! geoip2_db_path))
			return 0; /* GeoIP2 not configured or not working -- fail open. */
		if (context->geoip2_lookup_ret < 0)
			return c->args[1].not ? 0 : 1; /* IP lookup failed -- fail closed. */
		if (! context->geoip2_result) {
			if ((context->geoip2_lookup_ret = geoip2_lookup(geoip2_db_path, context->host_addr, &context->geoip2_result)) < 0) {
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
#endif

	if (c->type == COND_PHASEDONE) {
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
	if (e->action != NULL)
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
	if (s == t) {
		if (s[1]) {
			if ((s[1] == 'n') && (! s[2])) /* allow negation even on empty regexps */
				a->not = 1;
			else {
				yyerror("build_regex: empty expression with flags %s",
					a->src);
				return (1);
			}
		}
	} else {
		char *u;
		int flags = 0, r;

		u = malloc(s - t + 1);
		if (u == NULL) {
			yyerror("build_regex: malloc: %s", strerror(errno));
			return (1);
		}
		memcpy(u, t, s - t);
		u[s - t] = 0;
		s++;
		while (*s) {
			switch (*s) {
			case 'e':
				flags |= REG_EXTENDED;
				break;
			case 'i':
				flags |= REG_ICASE;
				break;
			case 'n':
				a->not = 1;
				break;
			default:
				yyerror("invalid flag %c in %s", *s, a->src);
				free(u);
				return (1);
			}
			++s;
		}
		if (!(flags & REG_EXTENDED))
			flags |= REG_BASIC;
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

				for (j = 0; j < 2; ++j)
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
