#ifndef MILTER_REGEX_H
#define MILTER_REGEX_H

#include "eval.h"

struct context {
	struct ruleset	*rs;
	int		*res;
	char		 buf[2048];	/* longer body lines are wrapped */
	unsigned	 pos;		/* write position within buf */
	char		 my_name[128];
	char		 message_id[64];
	char		 host_name[128];
	char		 host_addr[64];
	char		 helo[128];
	char		 auth_authen[128];
	char		 env_from[128];
	char		 env_rcpt[2048];
	char		 hdr_from[128];
	char		 hdr_to[128];
	char		 hdr_subject[128];
	char		*quarantine;
	int		 quarantine_lineno;
	int		 been_syslogged;
#ifdef GEOIP2
	int geoip2_lookup_ret;
	struct MMDB_lookup_result_s *geoip2_result;
	char *geoip2_result_summary;
	int cached_SMFIS_ACCEPT;
	int acceptnogeo;
#endif
};

extern void __attribute__((format(printf,3,4))) msg(int priority, struct context *context, const char *fmt, ...);

#if __linux__ || __sun__
size_t strlcat(char *dst, const char *src, size_t siz);
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif

#ifdef GEOIP2
extern const char *geoip2_db_path;
struct MMDB_lookup_result_s;
struct MMDB_entry_data_list_s;
extern int geoip2_opendb(const char *mmdb_path);
extern int geoip2_lookup(const char *mmdb_path, const char *ip_address, struct MMDB_lookup_result_s **result);
extern int geoip2_pick_leaf(struct MMDB_lookup_result_s *result, const char * const *lookup_path, struct MMDB_entry_data_list_s **leaf);
extern int geoip2_iterate_leaf(struct MMDB_entry_data_list_s **leaf, char *buf, size_t buf_spc, const char **s, int *s_len);
extern int geoip2_free_leaf(struct MMDB_entry_data_list_s *leaf);
extern int geoip2_release(struct MMDB_lookup_result_s **result);
extern int geoip2_closedb(void);

#endif

#endif /* MILTER_REGEX_H */
