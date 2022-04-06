// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <inttypes.h>
#include "builtin.h"
#include "perf.h"

#include "util/evlist.h" // for struct evsel_str_handler
#include "util/evsel.h"
#include "util/symbol.h"
#include "util/thread.h"
#include "util/header.h"

#include <subcmd/pager.h>
#include <subcmd/parse-options.h>
#include "util/trace-event.h"

#include "util/debug.h"
#include "util/session.h"
#include "util/tool.h"
#include "util/data.h"
#include "util/string2.h"

#include <sys/types.h>
#include <sys/prctl.h>
#include <semaphore.h>
#include <pthread.h>
#include <math.h>
#include <limits.h>

#include <linux/list.h>
#include <linux/hash.h>
#include <linux/kernel.h>
#include <linux/zalloc.h>
#include <linux/err.h>

static struct perf_session *session;

/* based on kernel/kvm_pagefaultdep.c */
#define LOCKHASH_BITS		12
#define LOCKHASH_SIZE		(1UL << LOCKHASH_BITS)

static struct hlist_head kvm_pagefault_hash_table[LOCKHASH_SIZE];

#define __kvm_pagefault_hashfn(key)	hash_long((unsigned long)key, LOCKHASH_BITS)
#define kvm_pagefault_hashentry(key)	(kvm_pagefault_hash_table + __kvm_pagefault_hashfn((key)))

#define ERROR_CODE_LEN		(1 << 3)
#define ERROR_CODE_MASK		(ERROR_CODE_LEN - 1)

struct kvm_pagefault_stat {
	struct hlist_node	hash_entry;
	struct rb_node		rb;		/* used for sorting */

	u64				addr;		/* address of fault address, used as ID */
	u64				ip;		/* FIXME. WIP */
	u64				nr_count;
	u64				error_code_stat[ERROR_CODE_LEN];
};

/* build simple key function one is bigger than two */
#define SINGLE_KEY(member)						\
	static int kvm_pagefault_stat_key_ ## member(struct kvm_pagefault_stat *one,	\
					 struct kvm_pagefault_stat *two)		\
	{								\
		return one->member > two->member;			\
	}

SINGLE_KEY(nr_count)

struct kvm_pagefault_key {
	/*
	 * name: the value for specify by user
	 * this should be simpler than raw name of member
	 * e.g. nr_acquired -> acquired, wait_time_total -> wait_total
	 */
	const char		*name;
	int			(*key)(struct kvm_pagefault_stat*, struct kvm_pagefault_stat*);
};

static const char		*sort_key = "count";

static int			(*compare)(struct kvm_pagefault_stat *, struct kvm_pagefault_stat *);

static struct rb_root		result;	/* place to store sorted data */

#define DEF_KEY_LOCK(name, fn_suffix)	\
	{ #name, kvm_pagefault_stat_key_ ## fn_suffix }
static struct kvm_pagefault_key keys[] = {
	DEF_KEY_LOCK(count, nr_count),

	/* extra comparisons much complicated should be here */

	{ NULL, NULL }
};

static int select_key(void)
{
	int i;

	for (i = 0; keys[i].name; i++) {
		if (!strcmp(keys[i].name, sort_key)) {
			compare = keys[i].key;
			return 0;
		}
	}

	pr_err("Unknown compare key: %s\n", sort_key);

	return -1;
}

static void insert_to_result(struct kvm_pagefault_stat *st,
			     int (*bigger)(struct kvm_pagefault_stat *, struct kvm_pagefault_stat *))
{
	struct rb_node **rb = &result.rb_node;
	struct rb_node *parent = NULL;
	struct kvm_pagefault_stat *p;

	while (*rb) {
		p = container_of(*rb, struct kvm_pagefault_stat, rb);
		parent = *rb;

		if (bigger(st, p))
			rb = &(*rb)->rb_left;
		else
			rb = &(*rb)->rb_right;
	}

	rb_link_node(&st->rb, parent, rb);
	rb_insert_color(&st->rb, &result);
}

/* returns left most element of result, and erase it */
static struct kvm_pagefault_stat *pop_from_result(void)
{
	struct rb_node *node = result.rb_node;

	if (!node)
		return NULL;

	while (node->rb_left)
		node = node->rb_left;

	rb_erase(node, &result);
	return container_of(node, struct kvm_pagefault_stat, rb);
}

static struct kvm_pagefault_stat *kvm_pagefault_stat_findnew(u64 addr, u64 ip)
{
	struct hlist_head *entry = kvm_pagefault_hashentry(addr);
	struct kvm_pagefault_stat *ret, *new;

	hlist_for_each_entry(ret, entry, hash_entry) {
		if (ret->addr == addr)
			return ret;
	}

	new = zalloc(sizeof(struct kvm_pagefault_stat));
	if (!new)
		goto alloc_failed;

	new->addr = addr;
	new->ip = ip;	/* FIXME. WIP */

	hlist_add_head(&new->hash_entry, entry);
	return new;

alloc_failed:
	pr_err("memory allocation failed\n");
	return NULL;
}

struct trace_kvm_pagefault_handler {
	int (*kvm_pagefault_event)(struct evsel *evsel,
			     struct perf_sample *sample);
};

static int report_kvm_pagefault_event(struct evsel *evsel,
				     struct perf_sample *sample)
{
	struct kvm_pagefault_stat *ks;

	/* Tracepoint format */
	u64 addr = evsel__intval(evsel, sample, "address");
	u64 ip = evsel__intval(evsel, sample, "ip");
	u64 error_code = evsel__intval(evsel, sample, "error_code");

	ks = kvm_pagefault_stat_findnew(addr, ip);
	if (!ks)
		return -ENOMEM;
	ks->error_code_stat[error_code & ERROR_CODE_MASK]++;
	ks->nr_count++;

	return 0;
}

/* kvm_pagefault oriented handlers */
/* TODO: handlers for CPU oriented, thread oriented */
static struct trace_kvm_pagefault_handler report_kvm_pagefault_ops  = {
	.kvm_pagefault_event		= report_kvm_pagefault_event,
};

static struct trace_kvm_pagefault_handler *trace_handler;

static int evsel__process_kvm_pagefault(struct evsel *evsel,
					     struct perf_sample *sample)
{
	if (trace_handler->kvm_pagefault_event)
		return trace_handler->kvm_pagefault_event(evsel, sample);
	return 0;
}

/* TODO: various way to print, coloring, nano or milli sec */
static void print_result(void)
{
	struct kvm_pagefault_stat *st;
	int total;

	pr_info("%20s ", "Address");
	pr_info("%10s ", "Count");

	pr_info("\n\n");

	total = 0;
	while ((st = pop_from_result())) {
		total++;
		pr_info("0x%016lx ", st->addr);
		pr_info("%20lu ", st->nr_count);

		pr_info("\n");
	}
}

static bool info_map;

static void dump_map(void)
{
	unsigned int i;
	struct kvm_pagefault_stat *st;

	pr_info("Address of instance: name of class\n");
	for (i = 0; i < LOCKHASH_SIZE; i++) {
		hlist_for_each_entry(st, &kvm_pagefault_hash_table[i], hash_entry) {
			pr_info(" 0x%016lx: %lu\n", st->addr, st->nr_count);
		}
	}
}

static int dump_info(void)
{
	int rc = 0;

	if (info_map)
		dump_map();
	else {
		rc = -1;
		pr_err("Unknown type of information\n");
	}

	return rc;
}

typedef int (*tracepoint_handler)(struct evsel *evsel,
				  struct perf_sample *sample);

static int process_sample_event(struct perf_tool *tool __maybe_unused,
				union perf_event *event,
				struct perf_sample *sample,
				struct evsel *evsel,
				struct machine *machine)
{
	int err = 0;
	struct thread *thread = machine__findnew_thread(machine, sample->pid,
							sample->tid);

	if (thread == NULL) {
		pr_debug("problem processing %d event, skipping it.\n",
			event->header.type);
		return -1;
	}

	if (evsel->handler != NULL) {
		tracepoint_handler f = evsel->handler;
		err = f(evsel, sample);
	}

	thread__put(thread);

	return err;
}

static void sort_result(void)
{
	unsigned int i;
	struct kvm_pagefault_stat *st;

	for (i = 0; i < LOCKHASH_SIZE; i++) {
		hlist_for_each_entry(st, &kvm_pagefault_hash_table[i], hash_entry) {
			insert_to_result(st, compare);
		}
	}
}

static const struct evsel_str_handler kvm_pagefault_tracepoints[] = {
	{ "exceptions:page_fault_user",	evsel__process_kvm_pagefault   }
};

static bool force;

static int __cmd_report(bool display_info)
{
	int err = -EINVAL;
	struct perf_tool eops = {
		.sample		 = process_sample_event,
		.comm		 = perf_event__process_comm,
		.namespaces	 = perf_event__process_namespaces,
		.ordered_events	 = true,
	};
	struct perf_data data = {
		.path  = input_name,
		.mode  = PERF_DATA_MODE_READ,
		.force = force,
	};

	session = perf_session__new(&data, &eops);
	if (IS_ERR(session)) {
		pr_err("Initializing perf session failed\n");
		return PTR_ERR(session);
	}

	symbol__init(&session->header.env);

	if (!perf_session__has_traces(session, "kvm_pagefault record"))
		goto out_delete;

	if (perf_session__set_tracepoints_handlers(session, kvm_pagefault_tracepoints)) {
		pr_err("Initializing perf session tracepoint handlers failed\n");
		goto out_delete;
	}

	if (select_key())
		goto out_delete;

	err = perf_session__process_events(session);
	if (err)
		goto out_delete;

	setup_pager();
	if (display_info) /* used for info subcommand */
		err = dump_info();
	else {
		sort_result();
		print_result();
	}

out_delete:
	perf_session__delete(session);
	return err;
}

static int __cmd_record(int argc, const char **argv)
{
	const char *record_args[] = {
		"record", "-R", "-m", "1024", "-c", "1",
	};
	unsigned int rec_argc, i, j, ret;
	const char **rec_argv;

	for (i = 0; i < ARRAY_SIZE(kvm_pagefault_tracepoints); i++) {
		if (!is_valid_tracepoint(kvm_pagefault_tracepoints[i].name)) {
				pr_err("tracepoint %s is not enabled.\n",
				       kvm_pagefault_tracepoints[i].name);
				return 1;
		}
	}

	rec_argc = ARRAY_SIZE(record_args) + argc - 1;
	/* factor of 2 is for -e in front of each tracepoint */
	rec_argc += 2 * ARRAY_SIZE(kvm_pagefault_tracepoints);

	rec_argv = calloc(rec_argc + 1, sizeof(char *));
	if (!rec_argv)
		return -ENOMEM;

	for (i = 0; i < ARRAY_SIZE(record_args); i++)
		rec_argv[i] = strdup(record_args[i]);

	for (j = 0; j < ARRAY_SIZE(kvm_pagefault_tracepoints); j++) {
		rec_argv[i++] = "-e";
		rec_argv[i++] = strdup(kvm_pagefault_tracepoints[j].name);
	}

	for (j = 1; j < (unsigned int)argc; j++, i++)
		rec_argv[i] = argv[j];

	BUG_ON(i != rec_argc);

	ret = cmd_record(i, rec_argv);
	free(rec_argv);
	return ret;
}

int cmd_pagefault(int argc, const char **argv)
{
	const struct option kvm_pagefault_options[] = {
	OPT_STRING('i', "input", &input_name, "file", "input file name"),
	OPT_INCR('v', "verbose", &verbose, "be more verbose (show symbol address, etc)"),
	OPT_BOOLEAN('D', "dump-raw-trace", &dump_trace, "dump raw trace in ASCII"),
	OPT_BOOLEAN('f', "force", &force, "don't complain, do it"),
	OPT_END()
	};

	const struct option info_options[] = {
	OPT_BOOLEAN('m', "map", &info_map,
		    "map of kvm_pagefault instances (address:name table)"),
	OPT_PARENT(kvm_pagefault_options)
	};

	const struct option report_options[] = {
	OPT_STRING('k', "key", &sort_key, "count",
		    "key for sorting (count)"),
	/* TODO: type */
	OPT_PARENT(kvm_pagefault_options)
	};

	const char * const info_usage[] = {
		"perf kvm_pagefault info [<options>]",
		NULL
	};
	const char *const kvm_pagefault_subcommands[] = { "record", "report", "script",
						 "info", NULL };
	const char *kvm_pagefault_usage[] = {
		NULL,
		NULL
	};
	const char * const report_usage[] = {
		"perf kvm_pagefault report [<options>]",
		NULL
	};
	unsigned int i;
	int rc = 0;

	for (i = 0; i < LOCKHASH_SIZE; i++)
		INIT_HLIST_HEAD(kvm_pagefault_hash_table + i);

	argc = parse_options_subcommand(argc, argv, kvm_pagefault_options, kvm_pagefault_subcommands,
					kvm_pagefault_usage, PARSE_OPT_STOP_AT_NON_OPTION);
	if (!argc)
		usage_with_options(kvm_pagefault_usage, kvm_pagefault_options);

	if (!strncmp(argv[0], "rec", 3)) {
		return __cmd_record(argc, argv);
	} else if (!strncmp(argv[0], "report", 6)) {
		trace_handler = &report_kvm_pagefault_ops;
		if (argc) {
			argc = parse_options(argc, argv,
					     report_options, report_usage, 0);
			if (argc)
				usage_with_options(report_usage, report_options);
		}
		rc = __cmd_report(false);
	} else if (!strcmp(argv[0], "script")) {
		/* Aliased to 'perf script' */
		return cmd_script(argc, argv);
	} else if (!strcmp(argv[0], "info")) {
		if (argc) {
			argc = parse_options(argc, argv,
					     info_options, info_usage, 0);
			if (argc)
				usage_with_options(info_usage, info_options);
		}
		/* recycling report_kvm_pagefault_ops */
		trace_handler = &report_kvm_pagefault_ops;
		rc = __cmd_report(true);
	} else {
		usage_with_options(kvm_pagefault_usage, kvm_pagefault_options);
	}

	return rc;
}
