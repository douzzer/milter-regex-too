/* $Id: parse.y,v 1.2 2011/07/16 13:52:07 dhartmei Exp $ */

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

%{
static const char rcsid[] = "$Id: parse.y,v 1.2 2011/07/16 13:52:07 dhartmei Exp $";

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libmilter/mfapi.h>

#include "eval.h"

int			 yyerror(const char *, ...);
static int		 yylex(void);

static int		 define_macro(const char *, struct expr *);
static struct expr	*find_macro(const char *);

static char		*err_str = NULL;
static size_t		 err_len = 0;
static const char	*infile = NULL;
static FILE		*fin = NULL;
static int		 lineno = 1;
static int		 errors = 0;
static struct ruleset	*rs = NULL;

struct macro {
	char		*name;
	struct expr	*expr;
	struct macro	*next;
} *macros = NULL;

typedef struct {
	union {
		char			*string;
		struct expr		*expr;
		struct expr_list	*expr_list;
		struct action		*action;
	} v;
	int lineno;
} YYSTYPE;
#define YYSTYPE_IS_DECLARED

%}

/* silence warnings for expected ambiguity in the AND and OR binary operators. */
%expect 4

%token	ERROR STRING
%token	ACCEPT WHITELIST REJECT TEMPFAIL DISCARD QUARANTINE
%token	CONNECT HELO ENVFROM ENVRCPT HEADER MACRO BODY PHASEDONE
%token	CAPTURE_ONCE_HEADER CAPTURE_ALL_HEADER
%token	CAPTURE_ONCE_BODY CAPTURE_ALL_BODY CAPTURE_MACRO
%token	COMPARE_HEADER COMPARE_CAPTURES
%token	CONNECTGEO HEADERGEO CAPTURE_ONCE_BODY_GEO CAPTURE_ALL_BODY_GEO
%token	CAPTURE_ONCE_HEADER_GEO CAPTURE_ALL_HEADER_GEO CAPTURE_MACRO_GEO
%token	AND OR NOT
%type	<v.string>	STRING
%type	<v.expr>	expr term
%type	<v.expr_list>	expr_l
%type	<v.action>	action
%%

file	: /* empty */
	| macro file		{ }
	| rule file		{ }
	| capture file		{ }
	;

rule	: action expr_l		{
		struct expr_list *el = $2, *eln;

		while (el != NULL) {
			eln = el->next;
			el->expr->action = $1;
			free(el);
			el = eln;
		}
	}
	;

macro	: STRING '=' expr	{
		if (define_macro($1, $3))
			YYERROR;
		free($1);
	}
	;

capture	: CAPTURE_ONCE_HEADER STRING STRING STRING	{
		if (! create_capture(rs, COND_CAPTURE_ONCE_HEADER, $2, $3, $4, NULL, yylval.lineno))
			YYERROR;
		free($2);
		free($3);
		free($4);
	}
	| CAPTURE_ALL_HEADER STRING STRING STRING	{
		if (! create_capture(rs, COND_CAPTURE_ALL_HEADER, $2, $3, $4, NULL, yylval.lineno))
			YYERROR;
		free($2);
		free($3);
		free($4);
	}
	| CAPTURE_ONCE_HEADER_GEO STRING STRING STRING STRING	{
#ifdef GEOIP2
		if (! create_capture(rs, COND_CAPTURE_ONCE_HEADER_GEO, $2, $3, $4, $5, yylval.lineno))
			YYERROR;
		free($2);
		free($3);
		free($4);
		free($5);
#else
		YYERROR;
#endif
	}
	| CAPTURE_ALL_HEADER_GEO STRING STRING STRING STRING	{
#ifdef GEOIP2
		if (! create_capture(rs, COND_CAPTURE_ALL_HEADER_GEO, $2, $3, $4, $5, yylval.lineno))
			YYERROR;
		free($2);
		free($3);
		free($4);
		free($5);
#else
		YYERROR;
#endif
	}
	| CAPTURE_ONCE_BODY STRING STRING	{
		if (! create_capture(rs, COND_CAPTURE_ONCE_BODY, $2, $3, NULL, NULL, yylval.lineno))
			YYERROR;
		free($2);
		free($3);
	}
	| CAPTURE_ALL_BODY STRING STRING	{
		if (! create_capture(rs, COND_CAPTURE_ALL_BODY, $2, $3, NULL, NULL, yylval.lineno))
			YYERROR;
		free($2);
		free($3);
	}
	| CAPTURE_ONCE_BODY_GEO STRING STRING STRING	{
#ifdef GEOIP2
		if (! create_capture(rs, COND_CAPTURE_ONCE_BODY_GEO, $2, $3, $4, NULL, yylval.lineno))
			YYERROR;
		free($2);
		free($3);
		free($4);
#else
		YYERROR;
#endif
	}
	| CAPTURE_ALL_BODY_GEO STRING STRING STRING	{
#ifdef GEOIP2
		if (! create_capture(rs, COND_CAPTURE_ALL_BODY_GEO, $2, $3, $4, NULL, yylval.lineno))
			YYERROR;
		free($2);
		free($3);
		free($4);
#else
		YYERROR;
#endif
	}
	| CAPTURE_MACRO STRING STRING STRING	{
		if (! create_capture(rs, COND_CAPTURE_MACRO, $2, $3, $4, NULL, yylval.lineno))
			YYERROR;
		free($2);
		free($3);
		free($4);
	}
	| CAPTURE_MACRO_GEO STRING STRING STRING STRING	{
#ifdef GEOIP2
		if (! create_capture(rs, COND_CAPTURE_MACRO_GEO, $2, $3, $4, $5, yylval.lineno))
			YYERROR;
		free($2);
		free($3);
		free($4);
		free($5);
#else
		YYERROR;
#endif
	}

action	: REJECT STRING		{
	$$ = create_action(rs, ACTION_REJECT, $2, yylval.lineno);
		if ($$ == NULL) {
			yyerror("yyparse: create_action");
			YYERROR;
		}
		free($2);
	}
	| TEMPFAIL STRING	{
		$$ = create_action(rs, ACTION_TEMPFAIL, $2, yylval.lineno);
		if ($$ == NULL) {
			yyerror("yyparse: create_action");
			YYERROR;
		}
		free($2);
	}
	| QUARANTINE STRING	{
		$$ = create_action(rs, ACTION_QUARANTINE, $2, yylval.lineno);
		if ($$ == NULL) {
			yyerror("yyparse: create_action");
			YYERROR;
		}
		free($2);
	}
	| DISCARD 		{
		$$ = create_action(rs, ACTION_DISCARD, "", yylval.lineno);
		if ($$ == NULL) {
			yyerror("yyparse: create_action");
			YYERROR;
		}
	}
	| ACCEPT 		{
		$$ = create_action(rs, ACTION_ACCEPT, "", yylval.lineno);
		if ($$ == NULL) {
			yyerror("yyparse: create_action");
			YYERROR;
		}
	}
	| WHITELIST 		{
		$$ = create_action(rs, ACTION_WHITELIST, "", yylval.lineno);
		if ($$ == NULL) {
			yyerror("yyparse: create_action");
			YYERROR;
		}
	}
	;

expr_l	: expr			{
		$$ = calloc(1, sizeof(struct expr_list));
		if ($$ == NULL) {
			yyerror("yyparse: calloc: %s", strerror(errno));
			YYERROR;
		}
		$$->expr = $1;
	}
	| expr_l expr		{
		$$ = calloc(1, sizeof(struct expr_list));
		if ($$ == NULL) {
			yyerror("yyparse: calloc: %s", strerror(errno));
			YYERROR;
		}
		$$->expr = $2;
		$$->next = $1;
	}
	;

expr	: term			{
		$$ = $1;
	}
	| expr AND expr	{
		$$ = create_expr(rs, EXPR_AND, $1, $3);
		if ($$ == NULL) {
			yyerror("yyparse: create_expr");
			YYERROR;
		}
	}
	| expr OR expr	{
		$$ = create_expr(rs, EXPR_OR, $1, $3);
		if ($$ == NULL) {
			yyerror("yyparse: create_expr");
			YYERROR;
		}
	}
	| NOT term		{
		$$ = create_expr(rs, EXPR_NOT, $2, NULL);
		if ($$ == NULL) {
			yyerror("yyparse: create_expr");
			YYERROR;
		}
	}
	;

term	: COMPARE_CAPTURES STRING STRING STRING STRING	{
		$$ = create_cond_4(rs, COND_COMPARE_CAPTURES, $2, $3, $4, $5, yylval.lineno);
		if ($$ == NULL)
			YYERROR;
		free($2);
		free($3);
		free($4);
		free($5);
	}
	| COMPARE_HEADER STRING STRING STRING STRING	{
		$$ = create_cond_4(rs, COND_COMPARE_HEADER, $2, $3, $4, $5, yylval.lineno);
		if ($$ == NULL)
			YYERROR;
		free($2);
		free($3);
		free($4);
		free($5);
	}
	| CONNECT STRING STRING	{
		$$ = create_cond(rs, COND_CONNECT, $2, $3, yylval.lineno);
		if ($$ == NULL)
			YYERROR;
		free($2);
		free($3);
	}
	| CONNECTGEO STRING STRING	{
#ifdef GEOIP2
		$$ = create_cond(rs, COND_CONNECTGEO, $2, $3, yylval.lineno);
		if ($$ == NULL)
			YYERROR;
		free($2);
		free($3);
#else
		YYERROR;
#endif
	}
	| HELO STRING		{
		$$ = create_cond(rs, COND_HELO, $2, NULL, yylval.lineno);
		if ($$ == NULL)
			YYERROR;
		free($2);
	}
	| ENVFROM STRING	{
		$$ = create_cond(rs, COND_ENVFROM, $2, NULL, yylval.lineno);
		if ($$ == NULL)
			YYERROR;
		free($2);
	}
	| ENVRCPT STRING	{
		$$ = create_cond(rs, COND_ENVRCPT, $2, NULL, yylval.lineno);
		if ($$ == NULL)
			YYERROR;
		free($2);
	}
	| HEADER STRING STRING	{
		$$ = create_cond(rs, COND_HEADER, $2, $3, yylval.lineno);
		if ($$ == NULL)
			YYERROR;
		free($2);
		free($3);
	}
	| HEADERGEO STRING STRING STRING STRING	{
#ifdef GEOIP2
		$$ = create_cond_4(rs, COND_HEADERGEO, $2, $3, $4, $5, yylval.lineno);
		if ($$ == NULL)
			YYERROR;
		free($2);
		free($3);
		free($4);
		free($5);
#else
		YYERROR;
#endif
	}
	| MACRO STRING STRING	{
		$$ = create_cond(rs, COND_MACRO, $2, $3, yylval.lineno);
		if ($$ == NULL)
			YYERROR;
		free($2);
		free($3);
	}
	| BODY STRING		{
		$$ = create_cond(rs, COND_BODY, $2, NULL, yylval.lineno);
		if ($$ == NULL)
			YYERROR;
		free($2);
	}
	| PHASEDONE STRING	{
		$$ = create_cond(rs, COND_PHASEDONE, $2, NULL, yylval.lineno);
		if ($$ == NULL)
			YYERROR;
		free($2);
	}
	| '(' expr ')'		{
		$$ = $2;
	}
	| '$' STRING		{
		$$ = find_macro($2);
		if ($$ == NULL) {
			yyerror("yyparse: undefined macro '%s'", $2);
			YYERROR;
		}
		free($2);
	}
	;

%%

int
__attribute__((format(printf,1,2)))
yyerror(const char *fmt, ...)
{
	va_list ap;
	errors = 1;

	if (err_str == NULL || err_len <= 0)
		return (0);
	va_start(ap, fmt);
	snprintf(err_str, err_len, "%s:%d: ", infile, yylval.lineno);
	vsnprintf(err_str + strlen(err_str), err_len - strlen(err_str),
	    fmt, ap);
	va_end(ap);
	return (0);
}

struct keywords {
	const char	*k_name;
	int		 k_val;
	enum { K_TYPE_COND, K_TYPE_EXPR, K_TYPE_ACTION } k_keyword_type;
	int		 k_keyword_id;
};

static int
kw_cmp(const void *k, const void *e)
{
	return (strcmp(k, ((struct keywords *)e)->k_name));
}

/* keep sorted */
static const struct keywords keywords[] = {
	{ "accept",	ACCEPT,		K_TYPE_ACTION,	ACTION_ACCEPT },
	{ "and",	AND,		K_TYPE_EXPR,	EXPR_AND },
	{ "body",	BODY,		K_TYPE_COND,	COND_BODY },
	{ "capture_all_body",	CAPTURE_ALL_BODY,		K_TYPE_COND,	COND_CAPTURE_ALL_BODY },
#ifdef GEOIP2
	{ "capture_all_body_geo",	CAPTURE_ALL_BODY_GEO,	K_TYPE_COND,	COND_CAPTURE_ALL_BODY_GEO },
#endif
	{ "capture_all_header",	CAPTURE_ALL_HEADER,		K_TYPE_COND,	COND_CAPTURE_ALL_HEADER },
#ifdef GEOIP2
	{ "capture_all_header_geo",	CAPTURE_ALL_HEADER_GEO,	K_TYPE_COND,	COND_CAPTURE_ALL_HEADER_GEO },
#endif
	{ "capture_macro",	CAPTURE_MACRO,		K_TYPE_COND,	COND_CAPTURE_MACRO },
#ifdef GEOIP2
	{ "capture_macro_geo",	CAPTURE_MACRO_GEO,	K_TYPE_COND,	COND_CAPTURE_MACRO_GEO },
#endif
	{ "capture_once_body",	CAPTURE_ONCE_BODY,		K_TYPE_COND,	COND_CAPTURE_ONCE_BODY },
#ifdef GEOIP2
	{ "capture_once_body_geo",	CAPTURE_ONCE_BODY_GEO,	K_TYPE_COND,	COND_CAPTURE_ONCE_BODY_GEO },
#endif
	{ "capture_once_header",	CAPTURE_ONCE_HEADER,		K_TYPE_COND,	COND_CAPTURE_ONCE_HEADER },
#ifdef GEOIP2
	{ "capture_once_header_geo",	CAPTURE_ONCE_HEADER_GEO,	K_TYPE_COND,	COND_CAPTURE_ONCE_HEADER_GEO },
#endif
	{ "compare_captures",	COMPARE_CAPTURES,	K_TYPE_COND,	COND_COMPARE_CAPTURES },
	{ "compare_header",	COMPARE_HEADER,		K_TYPE_COND,	COND_COMPARE_HEADER },
	{ "connect",	CONNECT,	K_TYPE_COND,	COND_CONNECT },
#ifdef GEOIP2
	{ "connectgeo",	CONNECTGEO,	K_TYPE_COND,	COND_CONNECTGEO },
#endif
	{ "discard",	DISCARD,	K_TYPE_ACTION,	ACTION_DISCARD },
	{ "envfrom",	ENVFROM,	K_TYPE_COND,	COND_ENVFROM },
	{ "envrcpt",	ENVRCPT,	K_TYPE_COND,	COND_ENVRCPT },
	{ "eoh",	-1,		K_TYPE_COND,	COND_EOH }, /* pseudo-cond used to track connection phase */
	{ "eom",	-1,		K_TYPE_COND,	COND_EOM }, /* pseudo-cond used to track connection phase */
	{ "header",	HEADER,		K_TYPE_COND,	COND_HEADER },
#ifdef GEOIP2
	{ "headergeo",	HEADERGEO,	K_TYPE_COND,	COND_HEADERGEO },
#endif
	{ "helo",	HELO,		K_TYPE_COND,	COND_HELO },
	{ "macro",	MACRO,		K_TYPE_COND,	COND_MACRO },
	{ "not",	NOT,		K_TYPE_EXPR,	EXPR_NOT },
	{ "or",		OR,		K_TYPE_EXPR,	EXPR_OR },
	{ "phasedone",	PHASEDONE,	K_TYPE_COND,	COND_PHASEDONE },
	{ "quarantine",	QUARANTINE,	K_TYPE_ACTION,	ACTION_QUARANTINE },
	{ "reject",	REJECT,		K_TYPE_ACTION,	ACTION_REJECT },
	{ "tempfail",	TEMPFAIL,	K_TYPE_ACTION,	ACTION_TEMPFAIL },
	{ "whitelist",	WHITELIST,	K_TYPE_ACTION,	ACTION_WHITELIST },
};

static int
lookup(char *s)
{
	const struct keywords *p;

	p = bsearch(s, keywords, sizeof(keywords) / sizeof(keywords[0]),
	    sizeof(keywords[0]), &kw_cmp);

	if (p)
		return (p->k_val);
	else
		return (STRING);
}

const char *
lookup_action_name(int action_type)
{
	for (const struct keywords *p = &keywords[0], *end = &keywords[sizeof keywords / sizeof keywords[0]]; p < end; ++p) {
		if (p->k_keyword_type != K_TYPE_ACTION)
			continue;
		if (p->k_keyword_id == action_type)
			return p->k_name;
	}
	return "";
}

const char *
lookup_cond_name(int cond_type)
{
	for (const struct keywords *p = &keywords[0], *end = &keywords[sizeof keywords / sizeof keywords[0]]; p < end; ++p) {
		if (p->k_keyword_type != K_TYPE_COND)
			continue;
		if (p->k_keyword_id == cond_type)
			return p->k_name;
	}
	return "";
}

static int
lgetc(FILE *f_in)
{
	int c, next;

restart:
	c = getc(f_in);
	if (c == '\\') {
		next = getc(f_in);
		if (next != '\n') {
			ungetc(next, f_in);
			return (c);
		}
		yylval.lineno = lineno;
		lineno++;
		goto restart;
	}
	return (c);
}

static int
lungetc(int c, FILE *f_in)
{
	return ungetc(c, f_in);
}

static int
yylex(void)
{
	int c;

top:
	yylval.lineno = lineno;

	while ((c = lgetc(fin)) == ' ' || c == '\t')
		;

	if (c == '#')
		while ((c = lgetc(fin)) != '\n' && c != EOF)
			;

	if (c == '\"' || c == '\'') {
		char del = c;
		char buf[8192], *p = buf;

		while ((c = lgetc(fin)) != EOF && c != del) {
			*p++ = c;
			if (p - buf >= (int)sizeof(buf) - 1) {
				yyerror("yylex: message too long");
				return (ERROR);
			}
		}
		*p = 0;
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL) {
			yyerror("yylex: strdup: %s", strerror(errno));
			return (ERROR);
		}
		return (STRING);
	}

	if (isalpha(c)) {
		char buf[8192], *p = buf;
		int token;

		do {
			*p++ = c;
			if (p - buf >= (int)sizeof(buf)) {
				yyerror("yylex: token too long");
				return (ERROR);
			}
		} while ((c = lgetc(fin)) != EOF &&
			 (isalpha(c) || isdigit(c) || (ispunct(c) && (c != '$') && (c != '(') && (c != ')'))));
		lungetc(c, fin);
		*p = 0;
		token = lookup(buf);
		if (token == STRING) {
			yylval.v.string = strdup(buf);
			if (yylval.v.string == NULL) {
				yyerror("yylex: strdup: %s", strerror(errno));
				return (ERROR);
			}
		}
		return (token);
	}

	if (c != '\n' && c != '(' && c != ')' && c != '=' && c != '$' &&
	    c != EOF) {
		char del = c;
		char buf[8192], *p = buf;

		*p++ = del;
		while ((c = lgetc(fin)) != EOF && c != '\n' && c != del) {
			*p++ = c;
			if (p - buf >= (int)sizeof(buf) - 1) {
				yyerror("yylex: argument too long");
				return (ERROR);
			}
		}
		if (c != EOF && c != '\n') {
			*p++ = del;
			while ((c = lgetc(fin)) != EOF && isalpha(c)) {
				*p++ = c;
				if (p - buf >= (int)sizeof(buf)) {
					yyerror("yylex: argument too long");
					return (ERROR);
				}
			}
		}
		if (c != EOF)
			lungetc(c, fin);
		*p = 0;
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL) {
			yyerror("yylex: strdup: %s", strerror(errno));
			return (ERROR);
		}
		return (STRING);
	}

	if (c == '\n') {
		lineno++;
		goto top;
	}

	if (c == EOF)
		return (0);

	return (c);
}

int
parse_ruleset(const char *f, struct ruleset **r, char *err, size_t len)
{
	*r = NULL;
	err_str = err;
	err_len = len;
	rs = create_ruleset();
	if (rs == NULL) {
		if (err_str != NULL && err_len > 0)
			snprintf(err_str, err_len, "create_ruleset");
		return (1);
	}
	infile = f;
	fin = fopen(infile, "rb");
	if (fin == NULL) {
		if (err_str != NULL && err_len > 0)
			snprintf(err_str, err_len, "fopen: %s: %s",
			    infile, strerror(errno));
		return (1);
	}
	lineno = 1;
	errors = 0;
	yyparse();
	fclose(fin);
	while (macros != NULL) {
		struct macro *m = macros->next;

		free(macros->name);
		free(macros);
		macros = m;
	}
	if (errors) {
		free_ruleset(rs);
		return (1);
	} else {
		*r = rs;
		return (0);
	}
}

static int
define_macro(const char *name, struct expr *e)
{
	struct macro *m = macros;

	while (m != NULL && strcmp(m->name, name))
		m = m->next;
	if (m != NULL) {
		yyerror("define_macro: macro '%s' already defined", name);
		return (1);
	}
	m = calloc(1, sizeof(struct macro));
	if (m == NULL) {
		yyerror("define_macro: calloc: %s", strerror(errno));
		return (1);
	}
	m->name = strdup(name);
	if (m->name == NULL) {
		yyerror("define_macro: strdup: %s", strerror(errno));
		free(m);
		return (1);
	}
	m->expr = e;
	m->next = macros;
	macros = m;
	return (0);
}

static struct expr *
find_macro(const char *name)
{
	struct macro *m = macros;

	while (m != NULL && strcmp(m->name, name))
		m = m->next;
	if (m == NULL)
		return (NULL);
	return (m->expr);
}
