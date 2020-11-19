/* $Id: eval.h,v 1.1.1.1 2007/01/11 15:49:52 dhartmei Exp $ */

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

#ifndef _EVAL_H_
#define _EVAL_H_

#ifdef USE_PCRE2
#include <pcre2posix.h>
#else
#include <regex.h>
#endif

enum { VAL_UNDEF=0, VAL_TRUE, VAL_FALSE };
typedef enum { COND_NONE=0, COND_CAPTURE_MACRO,
#ifdef GEOIP2
	       COND_CAPTURE_MACRO_GEO,
#endif
	       COND_MACRO, COND_CONNECT,
#ifdef GEOIP2
	       COND_CONNECTGEO,
#endif
	       COND_HELO, COND_ENVFROM, COND_ENVRCPT,
	       COND_CAPTURE_ONCE_HEADER, COND_CAPTURE_ALL_HEADER,
#ifdef GEOIP2
	       COND_CAPTURE_ONCE_HEADER_GEO, COND_CAPTURE_ALL_HEADER_GEO,
#endif
	       COND_COMPARE_HEADER, COND_COMPARE_CAPTURES,
	       COND_HEADER,
#ifdef GEOIP2
	       COND_HEADERGEO,
#endif
	       COND_BODY, COND_PHASEDONE, COND_MAX } cond_t;
enum { EXPR_AND, EXPR_OR, EXPR_NOT, EXPR_COND };
typedef enum { ACTION_NONE=0, ACTION_REJECT, ACTION_TEMPFAIL, ACTION_QUARANTINE,
	ACTION_DISCARD, ACTION_ACCEPT, ACTION_WHITELIST, ACTION_META } action_t;

struct expr;

struct cond {
	cond_t type; /* COND_MACRO...COND_MAX */
	struct cond_arg {
		char	*src;
		unsigned int	 empty:1;
		unsigned int	 not:1;
		unsigned int	 global:1;

		unsigned int	 compare_as_prefix:1;
		unsigned int	 compare_as_dname_prefix:1;
		unsigned int	 compare_as_suffix:1;
		unsigned int	 compare_as_dname_suffix:1;

#ifdef GEOIP2
		union {
			regex_t	 re;
			struct {
				char *geoip2_buf;
				char *geoip2_path[8];
			};
		};
#else
		regex_t	 re;
#endif
	}			 args[4];
	struct expr_list	*expr;
	unsigned		 idx;
};

struct cond_list {
	struct cond		*cond;
	struct cond_list	*next;
};

struct action;

struct expr {
	int			 type;
	struct expr		*args[2];
	struct cond		*cond;
	struct action		*action;
	struct expr_list	*expr;
	unsigned		 idx;
};

struct expr_list {
	struct expr		*expr;
	struct expr_list	*next;
};

struct action {
	action_t		 type;
	char			*msg;
	unsigned		 idx;
	int			 lineno;
};

struct action_list {
	struct action		*action;
	struct action_list	*next;
};

struct ruleset {
	struct cond_list	*cond[COND_MAX];
	struct action_list	*action;
	unsigned		 maxidx;
	int			 refcnt;
};

int		 eval_init(int);
extern int parse_ruleset(const char *, struct ruleset **, char *, size_t);
extern const char *lookup_action_name(int action_type);
extern const char *lookup_cond_name(int cond_type);
struct ruleset	*create_ruleset(void);
struct expr	*create_cond(struct ruleset *, int, const char *,
		    const char *);
extern struct expr *create_cond_4(struct ruleset *rs, int type, const char *a, const char *b, const char *c, const char *d);
struct expr	*create_expr(struct ruleset *, int, struct expr *,
		    struct expr *);
struct action	*create_action(struct ruleset *, int, const char *, int lineno);
struct context;
struct action	*eval_cond(struct context *context, int,
		    const char *, const char *);
struct action	*eval_end(struct context *context, int, int);
void		 eval_clear(struct context *context, int);
void		 free_ruleset(struct ruleset *);

struct kv_binding {
	struct kv_binding *prev, *next;
	const char *key;
	size_t val_len;
	char val[];
};

extern int insert_kv_binding(struct context *context, const char *key, const char *val, size_t val_len, struct kv_binding **point);
extern const char *get_kv_binding_next(const struct kv_binding **next);
const char *get_kv_binding_first(struct context *context, const char *key, const struct kv_binding **next);
void free_kv_bindings(struct kv_binding *list);

#endif
