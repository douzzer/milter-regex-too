#ifndef MILTER_REGEX_H
#define MILTER_REGEX_H

#include "eval.h"
#include <libmilter/mfapi.h>

#ifdef GEOIP2
#include <maxminddb.h>

struct MMDB_lookup_result_ll {
	struct MMDB_lookup_result_ll *next;
	char addr[64];
	struct MMDB_lookup_result_s result;
};
#endif

struct context {
	long long int	 created_at;
	unsigned long	 smfi_phases;
	long long int	 eval_time_cum;
	int		 check_cond_count;
	enum { MESSAGE_INPROGRESS=0, MESSAGE_ABORTED, MESSAGE_COMPLETED } message_status;
	struct ruleset	*rs;
	int		*res;
	char		 buf[2048];	/* longer body lines are wrapped */
	unsigned	 pos;		/* write position within buf */
	char		 my_name[128];
	char		 client_resolve[16];
	char		 tls_status[16];
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
	char		 end_eval_note[128];
	size_t		 body_start_offset;
	size_t		 body_end_offset;
	cond_t		 last_phase_done;
	const struct action *action;
	sfsistat	 action_result;
	long long int	 action_at;
#ifdef GEOIP2
	int geoip2_lookup_ret;
	struct MMDB_lookup_result_s *geoip2_result;
	struct MMDB_lookup_result_ll *geoip2_result_cache;
	char *geoip2_result_summary;
	struct MMDB_lookup_result_ll *geoip2_result_summary_cache_head;
#endif
};

extern void __attribute__((format(printf,3,4))) msg(int priority, struct context *context, const char *fmt, ...);
extern void __die(const char *fn, int lineno, int this_errno, const char *reason);
#define die(reason) __die(__FILE__, __LINE__, errno, reason)
#define die_with_errno(this_errno,reason) __die(__FILE__, __LINE__, this_errno, reason)

#if __linux__ || __sun__
size_t strlcat(char *dst, const char *src, size_t siz);
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif

extern const char gitversion[];
extern int debug;

#ifdef GEOIP2
extern const char *geoip2_db_path;
struct MMDB_lookup_result_s;
struct MMDB_entry_data_list_s;
extern int geoip2_opendb(const char *mmdb_path);
extern struct MMDB_lookup_result_s *geoip2_lookup(const char *mmdb_path, const char *ip_address, struct MMDB_lookup_result_ll **cache, int quiet_p);
extern int geoip2_pick_leaf(struct MMDB_lookup_result_s *result, const char * const *lookup_path, struct MMDB_entry_data_list_s **leaf);
extern int geoip2_iterate_leaf(struct MMDB_entry_data_list_s **leaf, char *buf, size_t buf_spc, const char **s, int *s_len);
extern int geoip2_free_leaf(struct MMDB_entry_data_list_s *leaf);
extern int geoip2_cache_release(struct MMDB_lookup_result_ll **cache);
extern int geoip2_closedb(void);

#endif

#endif /* MILTER_REGEX_H */
