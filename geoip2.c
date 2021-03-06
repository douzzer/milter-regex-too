/* adapted from libmaxminddb-1.3.2/bin/mmdblookup.c -- see http://dev.maxmind.com/ */
#define _GNU_SOURCE

#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <syslog.h>

#include <libgen.h>
#include <unistd.h>

#define LOCAL static
#define NO_PROTO

#include "milter-regex.h"

static pthread_rwlock_t db_lock = PTHREAD_RWLOCK_INITIALIZER;
static volatile int db_ok = 0;
static MMDB_s static_mmdb;
static volatile struct stat mmdb_st;

int geoip2_opendb(const char *fname) {
    int ret = -1;

    int rv = pthread_rwlock_wrlock(&db_lock);
    if (rv)
	die_with_errno(rv, "geoip2_opendb() pthread_rwlock_wrlock()");

    struct stat new_mmdb_st;
    if (stat(fname,&new_mmdb_st) < 0) {
	msg(LOG_CRIT, NULL, "geoip2_opendb() stat(%s): %s",fname,strerror(errno));
	goto out;
    }

    if (db_ok) {
	MMDB_close(&static_mmdb);
	db_ok = 0;
    }

    int status = MMDB_open(fname, MMDB_MODE_MMAP, &static_mmdb);

    if (status == MMDB_SUCCESS) {
	mmdb_st = new_mmdb_st;
	char mtime[32];
	struct tm mtime_tm;
	if (gmtime_r((const time_t *)&mmdb_st.st_mtime,&mtime_tm))
	    strftime(mtime, sizeof mtime, "%FT%TZ", &mtime_tm);
	else
	    mtime[0] = 0;
	msg(LOG_INFO, NULL, "opened %s, mtime %s, for GeoIP2 service", fname, mtime);
	db_ok = 1;
	ret = 0;
    } else {
        if (status == MMDB_IO_ERROR)
	    msg(LOG_CRIT, NULL, "geoip2_opendb() MMDB_open(): I/O error opening \"%s\": %s", fname, strerror(errno));
	else
	    msg(LOG_CRIT, NULL, "geoip2_opendb() MMDB_open(): error opening \"%s\": %s", fname, MMDB_strerror(status));
	goto out;
    }

    ret = 0;

 out:

    if ((rv=pthread_rwlock_unlock(&db_lock)))
	die_with_errno(rv, "geoip2_opendb() pthread_rwlock_unlock()");

    return ret;
}

int geoip2_closedb(void) {
    int rv = pthread_rwlock_wrlock(&db_lock);
    if (rv)
	die_with_errno(rv, "geoip2_closedb() pthread_rwlock_unlock()");
    MMDB_close(&static_mmdb);
    db_ok = 0;
    if ((rv=pthread_rwlock_unlock(&db_lock)))
	die_with_errno(rv, "geoip2_closedb() pthread_rwlock_unlock()");
    return 0;
}

struct MMDB_lookup_result_s *geoip2_lookup(const char *mmdb_path, const char *ip_address, struct MMDB_lookup_result_ll **cache, int quiet_p) {
    if (strlen(ip_address) >= sizeof (*cache)->addr) {
	errno = EINVAL;
	return 0;
    }
    for (struct MMDB_lookup_result_ll *i = *cache;
	 i;
	 i = i->next) {
	if (! strcasecmp(ip_address,i->addr)) {
	    if (! i->result.found_entry) {
		errno = ENOENT;
		return 0;
	    }
	    return &i->result;
	}
    }

    int rv;
    enum { FOR_NOTHING, FOR_READ, FOR_WRITE } db_locked = FOR_NOTHING;
    struct MMDB_lookup_result_ll *cacheent = 0;

    if (! db_ok)
	goto go_straight_to_write;

 open_read_only:
    if ((rv=pthread_rwlock_rdlock(&db_lock)))
	die_with_errno(rv, "geoip2_lookup() pthread_rwlock_rdlock()");
    db_locked = FOR_READ;

    if (! mmdb_path)
	goto done_checking_for_db_update;

 check_again:
    {
	struct stat new_mmdb_st;
	if (stat(mmdb_path,&new_mmdb_st) < 0)
	    goto done_checking_for_db_update;
	if ((! db_ok) ||
	    (new_mmdb_st.st_dev != mmdb_st.st_dev) ||
	    (new_mmdb_st.st_ino != mmdb_st.st_ino) ||
	    (new_mmdb_st.st_ctime != mmdb_st.st_ctime)) {

	    if (db_locked == FOR_READ) {
		if ((rv=pthread_rwlock_unlock(&db_lock)))
		    die_with_errno(rv, "geoip2_lookup() pthread_rwlock_unlock()");
		db_locked = FOR_NOTHING;
	    }

	    if (db_locked != FOR_WRITE) {
	    go_straight_to_write:
		if (geoip2_cache_release(cache) < 0)
		    die_with_errno(errno, "geoip2_lookup() geoip2_cache_release()");
		if (db_locked != FOR_NOTHING)
		    die_with_errno(-1,"geoip2_lookup() attempt to double-lock db_lock");
		if ((rv=pthread_rwlock_trywrlock(&db_lock))) {
		    msg(LOG_NOTICE, NULL, "geoip2_lookup() pthread_rwlock_trywrlock(): %s",strerror(rv));
		    if (! db_ok) {
			errno = rv;
			return 0;
		    }
		    mmdb_path = 0;
		    goto open_read_only;
		}
		db_locked = FOR_WRITE;
		goto check_again;
	    }

	    {
		MMDB_s new_mmdb;

		int status = MMDB_open(mmdb_path, MMDB_MODE_MMAP, &new_mmdb);
		if (status == MMDB_SUCCESS) {
		    mmdb_st = new_mmdb_st;
		    char mtime[32];
		    struct tm mtime_tm;
		    if (gmtime_r((const time_t *)&mmdb_st.st_mtime,&mtime_tm))
			strftime(mtime, sizeof mtime, "%FT%TZ", &mtime_tm);
		    else
			mtime[0] = 0;
		    msg(LOG_INFO, NULL, "%sopened %s, mtime %s, for GeoIP2 service", db_ok ? "re" : "", mmdb_path, mtime);
		    if (db_ok)
			MMDB_close(&static_mmdb);
		    else
			db_ok = 1;
		    static_mmdb = new_mmdb;
		} else {
		    if (status == MMDB_IO_ERROR)
			msg(LOG_ERR, NULL, "geoip2_lookup() MMDB_open(): I/O error reopening \"%s\": %s", mmdb_path, strerror(errno));
		    else
			msg(LOG_ERR, NULL, "geoip2_opendb() MMDB_open(): error reopening \"%s\": %s", mmdb_path, MMDB_strerror(status));
		}
	    }

	    if ((rv=pthread_rwlock_unlock(&db_lock)))
		die_with_errno(rv, "geoip2_lookup() pthread_rwlock_unlock()");
	    db_locked = FOR_NOTHING;
	    goto open_read_only;
	}
    }

 done_checking_for_db_update:

    if (! db_ok)
	goto err_out;

    if (db_locked == FOR_NOTHING)
	die_with_errno(-1,"attempt to access db without a lock");

    cacheent = malloc(sizeof **cache);
    if (! cacheent)
	goto err_out;

    strcpy(cacheent->addr,ip_address);

    int my_gai_error, mmdb_error;

    cacheent->result = MMDB_lookup_string(&static_mmdb, ip_address, &my_gai_error, &mmdb_error);

    if (my_gai_error != 0) {
	if (! quiet_p)
	    msg(LOG_NOTICE, 0, "geoip2_lookup() MMDB_lookup_string() getaddrinfo(%s): %s", ip_address, gai_strerror(my_gai_error));
	goto err_out;
    }

    if (mmdb_error != MMDB_SUCCESS) {
        msg(LOG_ERR, 0, "geoip2_lookup() MMDB_lookup_string(): %s", MMDB_strerror(mmdb_error));
	goto err_out;
    }

    cacheent->next = *cache;
    *cache = cacheent;

    if (! cacheent->result.found_entry) {
	errno = ENOENT;
	return 0;
    }

    return &cacheent->result;

err_out:
    if (cacheent)
	free(cacheent);
    if ((rv=pthread_rwlock_unlock(&db_lock)))
	die_with_errno(rv, "geoip2_lookup() pthread_rwlock_unlock()");
    return 0;
}

int geoip2_pick_leaf(MMDB_lookup_result_s *result, const char * const *lookup_path, MMDB_entry_data_list_s **leaf) {
    MMDB_entry_data_s entry_data;

    int status = MMDB_aget_value(&result->entry, &entry_data, lookup_path);
    if (status != MMDB_SUCCESS) {
	errno = ENOENT;
	return -1;
    } else if (! entry_data.offset) {
	errno = ENOENT;
	return -1;
    }

    MMDB_entry_s entry = { .mmdb = &static_mmdb, .offset = entry_data.offset };
    status = MMDB_get_entry_data_list(&entry, leaf);
    if (! *leaf) {
	errno = ENOENT;
	return -1;
    }

    return 0;
}

static int format_one(MMDB_entry_data_s *node, char *buf, size_t buf_spc, const char **s, int *s_len) {
    *s = buf; /* speculative */
    switch(node->type) {
    case MMDB_DATA_TYPE_EXTENDED:
    case MMDB_DATA_TYPE_POINTER:
    case MMDB_DATA_TYPE_ARRAY:
    case MMDB_DATA_TYPE_MAP:
    case MMDB_DATA_TYPE_CONTAINER:
    case MMDB_DATA_TYPE_END_MARKER:
    case MMDB_DATA_TYPE_BYTES:
	errno = EINVAL;
	return -1;
    case MMDB_DATA_TYPE_UTF8_STRING:
	*s = node->utf8_string;
	*s_len = (int)node->data_size;
	return 0;
    case MMDB_DATA_TYPE_DOUBLE:
	*s_len = snprintf(buf,buf_spc,"%0.6f",node->double_value);
	return 0;
    case MMDB_DATA_TYPE_FLOAT:
	*s_len = snprintf(buf,buf_spc,"%0.6f",(double)node->float_value);
	return 0;
    case MMDB_DATA_TYPE_UINT16:
	*s_len = snprintf(buf,buf_spc,"%hu",node->uint16);
	return 0;
    case MMDB_DATA_TYPE_UINT32:
	*s_len = snprintf(buf,buf_spc,"%u",node->uint16);
	return 0;
    case MMDB_DATA_TYPE_INT32:
	*s_len = snprintf(buf,buf_spc,"%d",node->int32);
	return 0;
    case MMDB_DATA_TYPE_UINT64:
	*s_len = snprintf(buf,buf_spc,"%llu",(long long unsigned int)node->uint64);
	return 0;
    case MMDB_DATA_TYPE_UINT128:
#if ULONG_MAX > 0xffffffffU
	if (node->uint128 <= (mmdb_uint128_t)~0UL)
	    *s_len = snprintf(buf,buf_spc,"0x%lx",(uint64_t)node->uint128);
	else
	    *s_len = snprintf(buf,buf_spc,"0x%lx%016lx",(uint64_t)(node->uint128 >> 64U),(uint64_t)node->uint128);
	return 0;
#else
	errno = ENOTSUP;
	return -1;
#endif
    case MMDB_DATA_TYPE_BOOLEAN:
	*s_len = snprintf(buf,buf_spc,"%s",node->boolean ? "true" : "false");
	return 0;
    }
    errno = EINVAL;
    return -1;
}

/* turn the leaf into regular (UTF8) strings usable with regexps. */
int geoip2_iterate_leaf(MMDB_entry_data_list_s **leaf, char *buf, size_t buf_spc, const char **s, int *s_len) {
    for (;;) {
	if (! *leaf) {
	    errno = ENOENT;
	    return -1;
	}
	if ((*leaf)->entry_data.has_data && (format_one(&(*leaf)->entry_data, buf, buf_spc, s, s_len) == 0))
	    break;
	*leaf = (*leaf)->next;
    }
    *leaf = (*leaf)->next;
    return 0;
}

int geoip2_free_leaf(MMDB_entry_data_list_s *leaf) {
    MMDB_free_entry_data_list(leaf);
    return 0;
}

int geoip2_cache_release(struct MMDB_lookup_result_ll **cache) {
    for (struct MMDB_lookup_result_ll *i = *cache,
	     *next;
	 i;
	 i = next) {
	next = i->next;
	free(i);
	int rv = pthread_rwlock_unlock(&db_lock);
	if (rv)
	    die_with_errno(rv, "geoip2_cache_release() pthread_rwlock_unlock()");
    }
    *cache = 0;
    return 0;
}

#ifdef TEST_GEOIP2

static int print_result(MMDB_lookup_result_s *result, const char **lookup_path, int lookup_path_length) {
    MMDB_entry_data_list_s *entry_data_list = NULL;
    int exit_code = 0;

    int status;
    if (lookup_path_length) {
	MMDB_entry_data_s entry_data;
	status = MMDB_aget_value(&result->entry, &entry_data, lookup_path);
	if (MMDB_SUCCESS == status) {
	    if (entry_data.offset) {
		MMDB_entry_s entry = { .mmdb = &static_mmdb, .offset = entry_data.offset };
		status = MMDB_get_entry_data_list(&entry, &entry_data_list);
	    } else
		fprintf(stdout, "\n  No data was found at the lookup path you provided\n\n");
	}
    } else
	status = MMDB_get_entry_data_list(&result->entry, &entry_data_list);

    if (MMDB_SUCCESS != status) {
	fprintf(stderr, "Got an error looking up the entry data - %s\n", MMDB_strerror(status));
	exit_code = 5;
	goto end;
    }

    if (NULL != entry_data_list) {
	fprintf(stdout, "\n");
	MMDB_dump_entry_data_list(stdout, entry_data_list, 2);
	fprintf(stdout, "\n");
    }

 end:
    if (entry_data_list)
	MMDB_free_entry_data_list(entry_data_list);

    return exit_code;
}

LOCAL void usage(char *program, int exit_code, const char *error);
LOCAL const char **get_options(
    int argc,
    char **argv,
    char **mmdb_file,
    char **ip_address,
    int *verbose,
    int *lookup_path_length);
LOCAL void dump_meta(MMDB_s *mmdb);

int main(int argc, char **argv)
{
    char *mmdb_file = NULL;
    char *ip_address = NULL;
    int verbose = 0;
    int lookup_path_length = 0;

    const char **lookup_path =
        get_options(argc, argv, &mmdb_file, &ip_address, &verbose,
                    &lookup_path_length);

    MMDB_lookup_result_s result;
    if (geoip2_lookup(mmdb_file, ip_address, &result) < 0)
	exit(2);

    if (verbose) {
        dump_meta(&static_mmdb);
    }

    int exitval = print_result(&result, lookup_path, lookup_path_length);

    geoip2_release(&result);
    MMDB_close(&static_mmdb);
    free(lookup_path);

    exit(exitval);
}

LOCAL void usage(char *program, int exit_code, const char *error)
{
    if (NULL != error) {
        fprintf(stderr, "\n  *ERROR: %s\n", error);
    }

    printf("\n"
                  "  %s --file /path/to/file.mmdb --ip 1.2.3.4 [path to lookup]\n"
                  "\n"
                  "  This application accepts the following options:\n"
                  "\n"
                  "      --file (-f)     The path to the MMDB file. Required.\n"
                  "\n"
                  "      --ip (-i)       The IP address to look up. Required.\n"
                  "\n"
                  "      --verbose (-v)  Turns on verbose output. Specifically, this causes this\n"
                  "                      application to output the database metadata.\n"
                  "\n"
                  "      --version       Print the program's version number and exit.\n"
                  "\n"
                  "      --help (-h -?)  Show usage information.\n"
                  "\n"
                  "  If an IP's data entry resolves to a map or array, you can provide\n"
                  "  a lookup path to only show part of that data.\n"
                  "\n"
                  "  For example, given a JSON structure like this:\n"
                  "\n"
                  "    {\n"
                  "        \"names\": {\n"
                  "             \"en\": \"Germany\",\n"
                  "             \"de\": \"Deutschland\"\n"
                  "        },\n"
                  "        \"cities\": [ \"Berlin\", \"Frankfurt\" ]\n"
                  "    }\n"
                  "\n"
                  "  You could look up just the English name by calling mmdblookup with a lookup path of:\n"
                  "\n"
                  "    mmdblookup --file ... --ip ... names en\n"
                  "\n"
                  "  Or you could look up the second city in the list with:\n"
                  "\n"
                  "    mmdblookup --file ... --ip ... cities 1\n"
                  "\n"
                  "  Array numbering begins with zero (0).\n"
                  "\n"
                  "  If you do not provide a path to lookup, all of the information for a given IP\n"
                  "  will be shown.\n"
	    "\n",
	   program);      

    exit(exit_code);
}

LOCAL const char **get_options(
    int argc,
    char **argv,
    char **mmdb_file,
    char **ip_address,
    int *verbose,
    int *lookup_path_length)
{
    static int help = 0;
    static int version = 0;

    while (1) {
        static struct option options[] = {
            { "file",      required_argument, 0, 'f' },
            { "ip",        required_argument, 0, 'i' },
            { "verbose",   no_argument,       0, 'v' },
            { "version",   no_argument,       0, 'n' },
#ifndef _WIN32
            { "threads",   required_argument, 0, 't' },
#endif
            { "help",      no_argument,       0, 'h' },
            { "?",         no_argument,       0, 1   },
            { 0,           0,                 0, 0   }
        };

        int opt_index;
#ifdef _WIN32
        char const * const optstring = "f:i:b:I:vnh?";
#else
        char const * const optstring = "f:i:b:t:I:vnh?";
#endif
        int opt_char = getopt_long(argc, argv, optstring, options,
                                   &opt_index);

        if (-1 == opt_char) {
            break;
        }

        if ('f' == opt_char) {
            *mmdb_file = optarg;
        } else if ('i' == opt_char) {
            *ip_address = optarg;
        } else if ('v' == opt_char) {
            *verbose = 1;
        } else if ('n' == opt_char) {
            version = 1;
        } else if ('h' == opt_char || '?' == opt_char) {
            help = 1;
        }
    }

#ifdef _WIN32
    char *program = alloca(strlen(argv[0]));
    _splitpath(argv[0], NULL, NULL, program, NULL);
    _splitpath(argv[0], NULL, NULL, NULL, program + strlen(program));
#else
    char *program = basename(argv[0]);
#endif

    if (help) {
        usage(program, 0, NULL);
    }

    if (NULL == *mmdb_file) {
        usage(program, 1, "You must provide a filename with --file");
    }

    if (*ip_address == NULL) {
        usage(program, 1, "You must provide an IP address with --ip");
    }

    const char **lookup_path =
        malloc(sizeof(const char *) * ((argc - optind) + 1));
    int i;
    for (i = 0; i < argc - optind; i++) {
        lookup_path[i] = argv[i + optind];
        (*lookup_path_length)++;
    }
    lookup_path[i] = NULL;

    return lookup_path;
}

LOCAL void dump_meta(MMDB_s *mmdb)
{

    char date[40];
    const time_t epoch = (const time_t)mmdb->metadata.build_epoch;
    strftime(date, 40, "%F %T UTC", gmtime(&epoch));

    printf("\n"
	   "  Database metadata\n"
	   "    Node count:    %i\n"
	   "    Record size:   %i bits\n"
	   "    IP version:    IPv%i\n"
	   "    Binary format: %i.%i\n"
	   "    Build epoch:   %lu (%s)\n"
	   "    Type:          %s\n"
	   "    Languages:     ",
            mmdb->metadata.node_count,
            mmdb->metadata.record_size,
            mmdb->metadata.ip_version,
            mmdb->metadata.binary_format_major_version,
            mmdb->metadata.binary_format_minor_version,
            mmdb->metadata.build_epoch,
            date,
            mmdb->metadata.database_type);

    for (size_t i = 0; i < mmdb->metadata.languages.count; i++) {
        fprintf(stdout, "%s", mmdb->metadata.languages.names[i]);
        if (i < mmdb->metadata.languages.count - 1) {
            fprintf(stdout, " ");
        }
    }
    fprintf(stdout, "\n");

    fprintf(stdout, "    Description:\n");
    for (size_t i = 0; i < mmdb->metadata.description.count; i++) {
        fprintf(stdout, "      %s:   %s\n",
                mmdb->metadata.description.descriptions[i]->language,
                mmdb->metadata.description.descriptions[i]->description);
    }
    fprintf(stdout, "\n");
}

#endif /* TEST_GEOIP2 */
