#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "eval.h"

extern int parse_ruleset(const char *, struct ruleset **, char *, size_t);

void
die(const char *reason)
{
	fprintf(stderr, "die() reason '%s'\n", reason);
}

int main(void)
{
	char err[8192];
	struct ruleset *rs = NULL;
	int *res;
	struct action *a;
	int i;

	for (i = 0; i < 10; ++i) {

	rs = NULL;
	if (parse_ruleset("rules", &rs, err, sizeof(err)) || rs == NULL) {
		fprintf(stderr, "parse_ruleset: %s\n", err);
		if (rs) {
			free_ruleset(rs);
			rs = NULL;
		}
		continue;
	}
	rs->refcnt++;
	printf("rules parsed ok! maxidx %u\n", rs->maxidx);
	res = calloc(1, rs->maxidx * sizeof(int));
	if (res == NULL) {
		fprintf(stderr, "calloc: %s\n", strerror(errno));
		return (1);
	}
	printf("body foo\n");
	a = eval_cond(rs, res, COND_BODY, "foo", NULL);
	if (a == NULL)
		printf("no action\n");
	else {
		printf("action found! msg '%s'\n", a->msg);
		goto done;
	}
	printf("body bar\n");
	a = eval_cond(rs, res, COND_BODY, "bar", NULL);
	if (a == NULL)
		printf("no action\n");
	else {
		printf("action found! msg '%s'\n", a->msg);
		goto done;
	}
	printf("end of body\n");
	a = eval_end(rs, res, COND_BODY, COND_MAX);
	if (a == NULL)
		printf("no action\n");
	else
		printf("action found! msg '%s'\n", a->msg);
	rs->refcnt--;
	free(res);
	free_ruleset(rs);

	}


done:
	return (0);
}
