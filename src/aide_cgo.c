#include "aide_cgo.h"
#include "aide.h"
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <stdbool.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "attributes.h"
#include "hashsum.h"
#include "rx_rule.h"
#include "url.h"
#include "commandconf.h"
#include "report.h"
#include "db_config.h"
#include "db_disk.h"
#include "db_lex.h"
#include "db.h"
#include "log.h"
#include "progress.h"
#include "seltree.h"
#include "errorcodes.h"
#include "gen_list.h"
#include "getopt.h"
#include "util.h"
#include "locale-aide.h"

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif

#ifdef WITH_GCRYPT
#include <gcrypt.h>
#define NEED_LIBGCRYPT_VERSION "1.8.0"
#endif

#define EXTRA_ATTR(attribute) fprintf(stdout, "%s: %s\n", attributes[attribute].config_name, extra_attributes&ATTR(attribute)?"yes":"no");

static void print_version(void) {
    fprintf(stdout, "AIDE %s\n\n", conf->aide_version);
    fprintf(stdout, "Compile-time options:\n%s\n", AIDECOMPILEOPTIONS);
    fprintf(stdout, "Default config values:\n");
    fprintf(stdout, "config file: %s\n", conf->config_file ? conf->config_file : "<none>");
#ifdef DEFAULT_DB
    fprintf(stdout, "database_in: %s\n", DEFAULT_DB);
#else
    fprintf(stdout, "database_in: <none>\n");
#endif
#ifdef DEFAULT_DB_OUT
    fprintf(stdout, "database_out: %s\n", DEFAULT_DB_OUT);
#else
    fprintf(stdout, "database_out: <none>\n");
#endif

    fprintf(stdout, "\nAvailable compiled-in attributes:\n");
    DB_ATTR_TYPE extra_attributes = get_groupval("X");
    EXTRA_ATTR(attr_acl)
    EXTRA_ATTR(attr_xattrs)
    EXTRA_ATTR(attr_selinux)
    EXTRA_ATTR(attr_e2fsattrs)
    EXTRA_ATTR(attr_capabilities)

    fprintf(stdout, "\nAvailable hashsum attributes:\n");
    DB_ATTR_TYPE available_hashsums = get_hashes(false);
    for (int i = 0; i < num_hashes; ++i) {
        fprintf(stdout, "%s: %s\n", attributes[hashsums[i].attribute].config_name, ATTR(hashsums[i].attribute)&available_hashsums ? "yes" : "no");
    }

    fprintf(stdout, "\nDefault compound groups:\n");
    char* predefined_groups[] = { "R", "L", ">", "H", "X" };
    for (unsigned long i = 0; i < sizeof(predefined_groups)/sizeof(char*); ++i) {
        char* str;
        fprintf(stdout, "%s: %s\n", predefined_groups[i], str = diff_attributes(0, get_groupval(predefined_groups[i])));
        free(str);
    }

    exit(0);
}





static void setdefaults_before_config(void) {
    DB_ATTR_TYPE X;

    conf = (db_config*)checked_malloc(sizeof(db_config));
    conf->defsyms = NULL;

    log_msg(LOG_LEVEL_INFO, "initialize rule tree");
    conf->tree = init_tree();
    conf->database_add_metadata = 1;
    conf->report_detailed_init = 0;
    conf->report_base16 = 0;
    conf->report_quiet = 0;
    conf->report_append = false;
    conf->report_ignore_added_attrs = 0;
    conf->report_ignore_removed_attrs = 0;
    conf->report_ignore_changed_attrs = 0;
    conf->report_force_attrs = 0;
#ifdef WITH_E2FSATTRS
    conf->report_ignore_e2fsattrs = 0UL;
#endif

    conf->check_path = NULL;
    conf->check_file_type = FT_REG;
    conf->report_urls = NULL;
    conf->report_level = default_report_options.level;
    conf->report_format = default_report_options.format;
    conf->config_file = CONFIG_FILE;
    conf->config_version = NULL;
    conf->aide_version = AIDEVERSION;
    conf->config_check_warn_unrestricted_rules = false;
#ifdef WITH_ACL
    conf->no_acl_on_symlinks = 0;
#endif
    conf->db_out_attrs = ATTR(attr_filename) | ATTR(attr_attr) | ATTR(attr_perm) | ATTR(attr_inode);
    conf->symlinks_found = 0;

    conf->database_in.url = NULL;
    conf->database_in.filename = NULL;
    conf->database_in.linenumber = 0;
    conf->database_in.linebuf = NULL;
    conf->database_in.fp = NULL;
#ifdef WITH_ZLIB
    conf->database_in.gzp = NULL;
#endif
    conf->database_in.lineno = 0;
    conf->database_in.fields = NULL;
    conf->database_in.num_fields = 0;
    conf->database_in.buffer_state = NULL;
    conf->database_in.mdc = NULL;
    conf->database_in.db_line = NULL;
    conf->database_in.created = false;

    conf->database_out.url = NULL;
    conf->database_out.filename = NULL;
    conf->database_out.linenumber = 0;
    conf->database_out.linebuf = NULL;
    conf->database_out.fp = NULL;
#ifdef WITH_ZLIB
    conf->database_out.gzp = NULL;
#endif
    conf->database_out.lineno = 0;
    conf->database_out.fields = NULL;
    conf->database_out.num_fields = 0;
    conf->database_out.buffer_state = NULL;
    conf->database_out.mdc = NULL;
    conf->database_out.db_line = NULL;
    conf->database_out.created = false;

    conf->database_new.url = NULL;
    conf->database_new.filename = NULL;
    conf->database_new.linenumber = 0;
    conf->database_new.linebuf = NULL;
    conf->database_new.fp = NULL;
#ifdef WITH_ZLIB
    conf->database_new.gzp = NULL;
#endif
    conf->database_new.lineno = 0;
    conf->database_new.fields = NULL;
    conf->database_new.num_fields = 0;
    conf->database_new.buffer_state = NULL;
    conf->database_new.mdc = NULL;
    conf->database_new.db_line = NULL;
    conf->database_new.created = false;

    conf->db_attrs = get_hashes(false);
#ifdef WITH_ZLIB
    conf->gzip_dbout = 0;
#endif

    conf->action = 0;
    conf->num_workers = -1;
    conf->warn_dead_symlinks = 0;
    conf->report_grouped = 1;
    conf->report_summarize_changes = 1;
    conf->root_prefix = NULL;
    conf->root_prefix_length = 0;
    conf->limit = NULL;
    conf->limit_crx = NULL;
    conf->groupsyms = NULL;
    conf->start_time = time(NULL);
    conf->progress = 0;
    conf->no_color = true;
    conf->print_details_width = 80;

    log_msg(LOG_LEVEL_INFO, "define default attribute definitions");
    for (ATTRIBUTE i = 0; i < num_attrs; ++i) {
        if (attributes[i].config_name) {
            do_groupdef(attributes[i].config_name, attributes[i].attr);
        }
    }

    X = 0LLU;
#ifdef WITH_ACL
    X |= ATTR(attr_acl);
#endif
#ifdef WITH_SELINUX
    X |= ATTR(attr_selinux);
#endif
#ifdef WITH_XATTR
    X |= ATTR(attr_xattrs);
#endif
#ifdef WITH_E2FSATTRS
    X |= ATTR(attr_e2fsattrs);
#endif
#ifdef WITH_CAPABILITIES
    X |= ATTR(attr_capabilities);
#endif

    DB_ATTR_TYPE common_attrs = ATTR(attr_perm) | ATTR(attr_ftype) | ATTR(attr_inode) | ATTR(attr_linkcount) | ATTR(attr_uid) | ATTR(attr_gid);
    DB_ATTR_TYPE GROUP_R_HASHES = 0LLU;

    log_msg(LOG_LEVEL_INFO, "define default groups definitions");
    do_groupdef("R", common_attrs | ATTR(attr_size) | ATTR(attr_linkname) | ATTR(attr_mtime) | ATTR(attr_ctime) | GROUP_R_HASHES | X);
    do_groupdef("L", common_attrs | ATTR(attr_linkname) | X);
    do_groupdef(">", common_attrs | ATTR(attr_size) | ATTR(attr_growing) | ATTR(attr_linkname) | X);
    do_groupdef("H", get_hashes(false));
    do_groupdef("X", X);
    do_groupdef("E", 0);
}

static void list_attribute(db_line* entry, ATTRIBUTE attribute) {
    char **value = NULL;
    int num, i, c;
    int p = conf->print_details_width - 5 - MAX_WIDTH_DETAILS_STRING;

    DB_ATTR_TYPE attr = ATTR(attribute);
    const char* name = attributes[attribute].details_string;

    num = get_attribute_values(attr, entry, &value, NULL);

    i = 0;
    while (i < num) {
        int olen = strlen(value[i]);
        int k = 0;
        while (olen - p * k >= 0) {
            c = k * (p - 1);
            fprintf(stdout, "  %-*s%c %.*s\n", MAX_WIDTH_DETAILS_STRING, (i + k) ? "" : name, (i + k) ? ' ' : ':', p - 1, olen - c > 0 ? &value[i][c] : "");
            k++;
        }
        ++i;
    }
    for (i = 0; i < num; ++i) { free(value[i]); value[i] = NULL; } free(value); value = NULL;
}


int aide_check_config(char* config_path, bool* version) {
    // use before, after, and config_path to check the configuration
    // get them from function arguments
    char* before = NULL;
    char* after = NULL;
    int errorno = 0;
    db_config* conf;

#ifdef WITH_LOCALE
    setlocale(LC_ALL, "");
    bindtextdomain(PACKAGE, LOCALEDIR);
    textdomain(PACKAGE);
#endif
    umask(0177);

    setdefaults_before_config();
    progress_status(PROGRESS_CONFIG, NULL);
    errorno = parse_config(before, config_path, after);
    if (errorno == RETFAIL) {
        exit(INVALID_CONFIGURELINE_ERROR);
    }
    
    free(before);
    free(after);
    if (*version == true) {
        print_version();
    } else {
        return 0;
    }
    return 0;
}
