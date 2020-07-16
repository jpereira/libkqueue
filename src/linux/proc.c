/*
 * Copyright (c) 2009 Mark Heily <mark@heily.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define __USE_GNU

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dlfcn.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <linux/un.h>
#include <linux/version.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14))
#   error "Platform don't support EVILT_PROC"
#endif
#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>

#include "sys/event.h"
#include "private.h"
#include "alloc.h"

#include "forkmonitor.h"

// Helpful to enable the debug only here.
#undef dbg_printf
#define dbg_printf(fmt, ...) do { \
    const char *f = strrchr(__FILE__, '/')+1; \
    fprintf(stderr, " ** dbg %s:%d %s(): " fmt"\n", f, __LINE__, __func__, ##__VA_ARGS__); \
} while(0)

// #undef dbg_printf
// #define dbg_printf(...)

# define RTLD_NEXT      ((void *) -1l)

static pid_t (*actual_fork)(void)  = NULL;
static pid_t (*actual_vfork)(void) = NULL;
static void  (*actual_abort)(void) = NULL;
static void  (*actual__exit)(int)  = NULL;
static void  (*actual__Exit)(int)  = NULL;
static int     commfd = 2;

#define MINIMUM_COMMFD  31

static void notify(const int type, struct message *const msg, const size_t extra)
{
    const int    saved_errno = errno;

    printf("######## Calling notify! = %d (%s)\n", type, type_name[type]);
    msg->pid  = getpid();
    msg->ppid = getppid();
    msg->sid  = getsid(0);
    msg->pgid = getpgrp();
    msg->uid  = getuid();
    msg->gid  = getgid();
    msg->euid = geteuid();
    msg->egid = getegid();
    msg->len  = extra;
    msg->type = type;

    /* Since we don't have any method of dealing with send() errors
     * or partial send()s, we just fire one off and hope for the best. */
    //send(commfd, msg, sizeof (struct message) + extra, MSG_EOR | MSG_NOSIGNAL);

    errno = saved_errno;
}

void libforkmonitor_init(void) __attribute__((constructor));
void libforkmonitor_init(void)
{
    const int saved_errno = errno;
    int       result;

    printf("######################## Initializing libforkmonitor_init()\n");

    /* Save the actual fork() call pointer. */
    if (!actual_fork)
        *(void **)&actual_fork = dlsym(RTLD_NEXT, "fork");

    /* Save the actual vfork() call pointer. */
    if (!actual_vfork)
        *(void **)&actual_vfork = dlsym(RTLD_NEXT, "vfork");

    /* Save the actual abort() call pointer. */
    if (!actual_abort)
        *(void **)&actual_abort = dlsym(RTLD_NEXT, "abort");

    /* Save the actual _exit() call pointer. */
    if (!actual__exit)
        *(void **)&actual__exit = dlsym(RTLD_NEXT, "_exit");
    if (!actual__exit)
        *(void **)&actual__exit = dlsym(RTLD_NEXT, "_Exit");

    /* Save the actual abort() call pointer. */
    if (!actual__Exit)
        *(void **)&actual__Exit = dlsym(RTLD_NEXT, "_Exit");
    if (!actual__Exit)
        *(void **)&actual__Exit = dlsym(RTLD_NEXT, "_exit");

    // socketfd = socket(AF_UNIX, SOCK_DGRAM, 0);
#if 0
    /* Open an Unix domain datagram socket to the observer. */
    if (commfd == -1) {
        const char *address;

        /* Connect to where? */
        address = getenv(FORKMONITOR_ENVNAME);
        if (address && *address) {
            struct sockaddr_un addr;

            memset(&addr, 0, sizeof addr);
            addr.sun_family = AF_UNIX;
            strncpy(addr.sun_path, address, sizeof addr.sun_path - 1);

            /* Create and bind the socket. */
            commfd = socket(AF_UNIX, SOCK_DGRAM, 0);
            if (commfd != -1) {
                int cu = connect(commfd, (const struct sockaddr *)&addr, sizeof (addr));

                if (cu == -1) {
                    /* Failed. Close the socket. */
                    do {
                        result = close(commfd);
                    } while (result == -1 && errno == EINTR);
                    commfd = -1;
                }
            }

            /* Move commfd to a high descriptor, to avoid complications. */
            if (commfd != -1 && commfd < MINIMUM_COMMFD) {
                const int newfd = MINIMUM_COMMFD;
                do {
                    result = dup2(commfd, newfd);
                } while (result == -1 && errno == EINTR);
                if (!result) {
                    do {
                        result = close(commfd);
                    } while (result == -1 && errno == EINTR);
                    commfd = newfd;
                }
            }
        }
    }

    /* Send an init message, listing the executable path. */
    if (commfd != -1) {
        size_t          len = 128;
        struct message *msg = NULL;

        while (1) {
            ssize_t n;

            free(msg);
            msg = malloc(sizeof (struct message) + len);
            if (!msg) {
                len = 0;
                break;
            }

            n = readlink("/proc/self/exe", msg->data, len);
            if (n > (ssize_t)0 && (size_t)n < len) {
                msg->data[n] = '\0';
                len = n + 1;
                break;
            }

            len = (3 * len) / 2;
            if (len >= 65536U) {
                free(msg);
                msg = NULL;
                len = 0;
                break;
            }
        }

        if (len > 0) {
            /* INIT message with executable name */
            notify(TYPE_EXEC, msg, len);
            free(msg);
        } else {
            /* INIT message without executable name */
            struct message msg2;
            notify(TYPE_EXEC, &msg2, sizeof msg2);
        }
    }
#endif

    /* Restore errno. */
    errno = saved_errno;
}

void libforkmonitor_done(void) __attribute__((destructor));
void libforkmonitor_done(void)
{
    const int saved_errno = errno;
    int       result;

    /* Send an exit message, no data. */
    if (commfd != -1) {
        struct message msg;
        notify(TYPE_DONE, &msg, sizeof msg);
    }

    /* If commfd is open, close it. */
    if (commfd != -1) {
        do {
            result = close(commfd);
        } while (result == -1 && errno == EINTR);
    }

    /* Restore errno. */
    errno = saved_errno;
}

/*
 * Hooked C library functions.
*/

pid_t fork(void)
{
    pid_t result;

    printf("!!!!!!!!!!!!!!!!!!! Buuuuuceta\n");
    if (!actual_fork) {
        const int saved_errno = errno;

        *(void **)&actual_fork = dlsym(RTLD_NEXT, "fork");
        if (!actual_fork) {
            errno = EAGAIN;
            return (pid_t)-1;
        }

        errno = saved_errno;
    }

    result = actual_fork();
    if (!result && commfd != -1) {
        struct message msg;
        notify(TYPE_FORK, &msg, sizeof msg);
    }

    return result;
}

pid_t vfork(void)
{
    pid_t result;

    if (!actual_vfork) {
        const int saved_errno = errno;

        *(void **)&actual_vfork = dlsym(RTLD_NEXT, "vfork");
        if (!actual_vfork) {
            errno = EAGAIN;
            return (pid_t)-1;
        }

        errno = saved_errno;
    }

    result = actual_vfork();
    if (!result && commfd != -1) {
        struct message msg;
        notify(TYPE_VFORK, &msg, sizeof msg);
    }

    return result;
}

void _exit(const int code)
{
    if (!actual__exit) {
        const int saved_errno = errno;
        *(void **)&actual__exit = dlsym(RTLD_NEXT, "_exit");
        if (!actual__exit)
            *(void **)&actual__exit = dlsym(RTLD_NEXT, "_Exit");
        errno = saved_errno;
    }

    if (commfd != -1) {
        struct {
            struct message  msg;
            int             extra;
        } data;

        memcpy(&data.msg.data[0], &code, sizeof code);
        notify(TYPE_EXIT, &(data.msg), sizeof (struct message) + sizeof (int));
    }

    if (actual__exit)
        actual__exit(code);

    exit(code);
}

void _Exit(const int code)
{
    if (!actual__Exit) {
        const int saved_errno = errno;
        *(void **)&actual__Exit = dlsym(RTLD_NEXT, "_Exit");
        if (!actual__Exit)
            *(void **)&actual__Exit = dlsym(RTLD_NEXT, "_exit");
        errno = saved_errno;
    }

    if (commfd != -1) {
        struct {
            struct message  msg;
            int             extra;
        } data;

        memcpy(&data.msg.data[0], &code, sizeof code);
        notify(TYPE_EXIT, &(data.msg), sizeof (struct message) + sizeof (int));
    }

    if (actual__Exit)
        actual__Exit(code);

    exit(code);
}

void abort(void)
{
    if (!actual_abort) {
        const int saved_errno = errno;
        *(void **)&actual_abort = dlsym(RTLD_NEXT, "abort");
        errno = saved_errno;
    }

    if (commfd != -1) {
        struct message msg;
        notify(TYPE_ABORT, &msg, sizeof msg);
    }

    actual_abort();
    exit(127);
}



/**
 * @File: src/linux/proc.c
 * @Author: Jorge Pereira <jpereira@freeradius.org>
 * @Desc: Based on FreeBSD kevent() manual https://www.freebsd.org/cgi/man.cgi?query=kqueue&sektion=2
 */

/**
 *  EVFILT_PROC      Takes the process ID to monitor as the identifier and
 *                   the events to watch for in fflags, and returns when the
 *                   process performs one or more of the requested events.
 *                   If a process can normally see another process, it can
 *                   attach an event to it.  The events to monitor are:
 *
 *                   NOTE_EXIT    The process has exited. The exit status will
 *                                be stored in data.
 *
 *                   NOTE_EXITSTATUS (Only OSX)
 *                                The process has exited and its exit status
 *                                is in filter specific data. Valid only on
 *                                child processes and to be used along with
 *                                NOTE_EXIT.
 *
 *                   NOTE_FORK    The process has called fork().
 *
 *                   NOTE_EXEC    The process executed a new process via
 *                                execve(2) or similar call.
 *
 *                   NOTE_SIGNAL  (Only OSX)
 *                                The process was sent a signal. Status can
 *                                be checked via waitpid(2) or similar call.
 *
 *                   NOTE_REAP    The process was reaped by the parent via
 *                                wait(2) or similar call. Deprecated, use
 *                                NOTE_EXIT.
 *
 *                   NOTE_TRACK   Follow a process across fork()
 *                                calls.  The parent process regis-
 *                                ters a new kevent to monitor the
 *                                child process using the same fflags
 *                                as the original event.  The child
 *                                process will signal an event with
 *                                NOTE_CHILD set in fflags and the
 *                                parent PID in data.
 *
 *                                If the parent process fails to reg-
 *                                ister a new kevent (usually due to
 *                                resource limitations), it will sig-
 *                                nal an event with NOTE_TRACKERR set
 *                                in fflags, and the child process
 *                                will not signal a NOTE_CHILD event.
 *
 *                   On return, fflags contains the events which triggered
 *                   the filter.
 */
struct kproc_info {
    int   proc_event; // <! Process event. e.g: FORK/EXEC/EXIT
    pid_t parent_pid; // <! Parent Process Id
    pid_t child_pid;  // <! Process Id
    int   exit_code;  // <! Exit status code
    int   fd;         // <! epoll_ctl(ADD) file descriptor
};

/**
 * Thread monitor data struct
 */
#define MAX_PROC_BUFF 8
struct evfilt_data {
    int              nl_fd;              // <! Netlink channel
    pthread_t        wthr_dispatcher_id; // <!
    pthread_t        wthr_observer_id;   // <!
    pthread_cond_t   wait_cond;          // <!
    pthread_mutex_t  wait_mtx;           // <!

    /* Circular buffer with the latest process */
    int proc_pos;
    struct kproc_info proc_buff[MAX_PROC_BUFF];
};

/**
 * Netlink data msg struct
 */
struct nlcn_msg {
    struct nlmsghdr nl_hdr;
    struct __attribute__ ((__packed__)) {
        struct cn_msg cn_msg;
        struct proc_event proc_ev;
    };
};

static sig_atomic_t __thread need_exit     = false;
static int proc_filter_instances           = 0;
static bool proc_thread_observer_started   = false;
static bool proc_thread_dispatcher_started = false;

/* Only the events needed */
#define GET_PROC_EVENT_NAME(x)  ((x == PROC_EVENT_FORK) ? "FORK" : \
                                 (x == PROC_EVENT_EXEC) ? "EXEC" : \
                                 (x == PROC_EVENT_EXIT) ? "EXIT" : "Unknown")

#ifdef NDEBUG
#   define nl_proc_event_dump(pe)
#   define proc_status_dump(pid, status)
#else
static const char *
proc_status_dump(pid_t pid, int status) {
    static __thread char buf[128];

    if (WIFEXITED(status)) {
        snprintf(buf, sizeof(buf), "(NOTE_EXIT|NOTE_EXITSTATUS): Process %d exited with status %d.", pid, WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        snprintf(buf, sizeof(buf), "(NOTE_EXIT|NOTE_SIGNAL): Process %d killed by signal %d.", pid, WTERMSIG(status));
    } else {
        snprintf(buf, sizeof(buf), "(NOTE_EXIT): Process %d terminated.", pid);
    }

    return buf;
}

static const char *
nl_proc_event_dump(const struct proc_event *pe) {
    static __thread char buf[256];

    assert(pe != NULL);

    switch (pe->what) {
        case PROC_EVENT_NONE:
            snprintf(buf, sizeof(buf), "proc_event=%p: PROC_EVENT_NONE { NULL }", pe);
            break;
        case PROC_EVENT_FORK:
            snprintf(buf, sizeof(buf), "proc_event=%p: PROC_EVENT_FORK { parent(pid,tgid)=%d,%d -> child(pid,tgid)=%d,%d }",
                    pe,
                    pe->event_data.fork.parent_pid,
                    pe->event_data.fork.parent_tgid,
                    pe->event_data.fork.child_pid,
                    pe->event_data.fork.child_tgid);
            break;
        case PROC_EVENT_EXEC:
            snprintf(buf, sizeof(buf), "proc_event=%p: PROC_EVENT_EXEC { tid=%d pid=%d }",
                    pe,
                    pe->event_data.exec.process_pid,
                    pe->event_data.exec.process_tgid);
            break;
        case PROC_EVENT_UID:
            snprintf(buf, sizeof(buf), "proc_event=%p: PROC_EVENT_UID { tid=%d pid=%d from %d to %d }",
                    pe,
                    pe->event_data.id.process_pid,
                    pe->event_data.id.process_tgid,
                    pe->event_data.id.r.ruid,
                    pe->event_data.id.e.euid);
            break;
        case PROC_EVENT_GID:
            snprintf(buf, sizeof(buf), "proc_event=%p: PROC_EVENT_GID { change: tid=%d pid=%d from %d to %d }",
                    pe,
                    pe->event_data.id.process_pid,
                    pe->event_data.id.process_tgid,
                    pe->event_data.id.r.rgid,
                    pe->event_data.id.e.egid);
            break;
        case PROC_EVENT_EXIT:
            snprintf(buf, sizeof(buf), "proc_event=%p: PROC_EVENT_EXIT { pid=%d tgid=%d exit_code=%d, exit_signal=%d, parent_pid=%d, parent_tgid=%d }",
                    pe,
                    pe->event_data.exit.process_pid,
                    pe->event_data.exit.process_tgid,
                    pe->event_data.exit.exit_code,
                    pe->event_data.exit.exit_signal,
                    pe->event_data.exit.parent_pid,
                    pe->event_data.exit.parent_tgid);
            break;
        case PROC_EVENT_COMM:
            snprintf(buf, sizeof(buf), "proc_event=%p: PROC_EVENT_COMM { pid=%d tgid=%d }",
                    pe,
                    pe->event_data.comm.process_pid,
                    pe->event_data.comm.process_tgid);
            break;
        default:
            snprintf(buf, sizeof(buf), "proc_event=%p: unhandled proc event: %d", pe, pe->what);
            break;
    }

    return buf;
}
#endif

#define GOT_TGID        (0x01)
#define GOT_PPID        (0x02)
#define GOT_ALL         (GOT_TGID | GOT_PPID)
/*
 *  get_parent_pid()
 *  get parent pid and set is_thread to true if process
 *  not forked but a newly created thread
 */
static pid_t get_parent_pid(const pid_t pid, bool * const is_thread)
{
    FILE *fp;
    pid_t tgid = 0, parent_pid = 0;
    unsigned int got = 0;
    char path[PATH_MAX];
    char buffer[4096];

    *is_thread = false;
    (void)snprintf(path, sizeof(path), "/proc/%u/status", pid);
    fp = fopen(path, "r");
    if (!fp)
        return 0;

    while (((got & GOT_ALL) != GOT_ALL) &&
           (fgets(buffer, sizeof(buffer), fp) != NULL)) {
        if (!strncmp(buffer, "Tgid:", 5)) {
            if (sscanf(buffer + 5, "%u", &tgid) == 1) {
                got |= GOT_TGID;
            } else {
                tgid = 0;
            }
        }
        if (!strncmp(buffer, "PPid:", 5)) {
            if (sscanf(buffer + 5, "%u", &parent_pid) == 1)
                got |= GOT_PPID;
            else
                parent_pid = 0;
        }
    }
    (void)fclose(fp);

    if ((got & GOT_ALL) == GOT_ALL) {
        /*  TGID and PID are not the same if it is a thread */
        if (tgid != pid) {
            /* In this case, the parent is the TGID */
            parent_pid = tgid;
            *is_thread = true;
        }
    } else {
        parent_pid = 0;
    }

    return parent_pid;
}

/*
 *  Netlink wire Kernel setup.
 */
static int
nl_init()
{
    int sock;
    struct sockaddr_nl nlcn_bind = {
        .nl_family = AF_NETLINK,
        .nl_groups = CN_IDX_PROC,
        .nl_pid = getpid()
    };
    struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr nl_hdr;
        struct __attribute__ ((__packed__)) {
            struct cn_msg cn_msg;
            enum proc_cn_mcast_op cn_mcast;
        };
    } nlcn_init_msg = {
        .nl_hdr.nlmsg_len = sizeof(nlcn_init_msg),
        .nl_hdr.nlmsg_pid = getpid(),
        .nl_hdr.nlmsg_type = NLMSG_DONE,
        .nl_hdr.nlmsg_flags = 0,
        .nl_hdr.nlmsg_seq = 0,

        .cn_msg.id.idx = CN_IDX_PROC,
        .cn_msg.id.val = CN_VAL_PROC,
        .cn_msg.seq = 0,
        .cn_msg.ack = 0,
        .cn_msg.len = sizeof(enum proc_cn_mcast_op),

        .cn_mcast = PROC_CN_MCAST_LISTEN
    };

    if ((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR)) < 0) {
        dbg_perror("netlink socket(2)");
        return -1;
    }

    if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK) < 0) {
        dbg_perror("netlink fcntl(2)");
    error:
        close(sock);
        return -1;
    }

    if (bind(sock, (struct sockaddr *)&nlcn_bind, sizeof(nlcn_bind)) < 0) {
        dbg_perror("netlink bind(2)");
        goto error;
    }

    if (send(sock, &nlcn_init_msg, sizeof(nlcn_init_msg), 0) < 0) {
        dbg_perror("netlink send(2)");
        goto error;
    }

    return sock;
}

static void
proc_thread_on_sigint(UNUSED int unused)
{
    dbg_printf("Received Ctrl+C, stopping proc_thread_loop()");
    need_exit = true;
}

/**
 *  Thread in charge to care about all process events.
 */
void *
proc_thread_observer(void *arg)
{
    struct filter *filt = arg;
    struct evfilt_data *kf_data = filt->kf_data;
    sigset_t sigmask;

    dbg_printf("tid=%ld instances=%d - Process observer thread started", syscall(SYS_gettid), proc_filter_instances);

    assert(kf_data->nl_fd >= 0);
    assert(proc_filter_instances == 1);

    /* Block all signals */
    sigfillset (&sigmask);
    pthread_sigmask(SIG_BLOCK, &sigmask, NULL);

    /* Catch any Ctrl-C and try to finalize the thread */
    signal(SIGINT, &proc_thread_on_sigint);
    siginterrupt(SIGINT, true);

    proc_thread_observer_started = true;

    while (!need_exit) {
        int rc;
        struct kproc_info kproc_tmp = { -1, };
        struct nlcn_msg nlcn_msg = { 0, };
        bool is_thread = false;

        /**
         *  Retrieve all process events from the Kernel.
         */
        rc = recv(kf_data->nl_fd, &nlcn_msg, sizeof(nlcn_msg), 0);
        if (rc == 0) {  /* shutdown? */
            dbg_printf("netlink recv(2): shutdown");
            return NULL;
        } else if (rc < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* It's not *really* ready for recv; wait until it is. */
                continue;
            }

            dbg_perror("netlink recv(2)");
            return NULL;
        }

        /* Check if one of these events are FORK, EXIT or EXEC */
        kproc_tmp.proc_event = nlcn_msg.proc_ev.what;
        switch (kproc_tmp.proc_event) {
            case PROC_EVENT_FORK: /* NOTE_FORK | NOTE_CHILD */
                kproc_tmp.parent_pid = nlcn_msg.proc_ev.event_data.fork.parent_pid;
                kproc_tmp.child_pid  = nlcn_msg.proc_ev.event_data.fork.child_pid;
                kproc_tmp.exit_code  = -1;
            break;

            case PROC_EVENT_EXEC: /* NOTE_EXEC */
                kproc_tmp.parent_pid = nlcn_msg.proc_ev.event_data.exec.process_pid;
                kproc_tmp.child_pid  = nlcn_msg.proc_ev.event_data.exec.process_tgid;
                kproc_tmp.exit_code  = -1;
            break;

            case PROC_EVENT_EXIT: /* NOTE_EXIT | NOTE_EXITSTATUS | NOTE_SIGNAL */
                kproc_tmp.parent_pid = nlcn_msg.proc_ev.event_data.exit.process_pid;
                kproc_tmp.child_pid  = nlcn_msg.proc_ev.event_data.exit.process_tgid;
                kproc_tmp.exit_code  = nlcn_msg.proc_ev.event_data.exit.exit_code;
            break;

            default:
                continue;
        }

        /* Push into the circular buffer */
        {
            int pos = (kf_data->proc_pos++ % MAX_PROC_BUFF);

            /**
             * The nl_proc_event_dump() is very verbose. Only useful to enable during troubleshooting.
             */
#if 0
            dbg_printf("Buffering at pos=%d %s", pos, nl_proc_event_dump((void *)&nlcn_msg.proc_ev));
#endif

            memcpy(&kf_data->proc_buff[pos], &kproc_tmp, sizeof(kproc_tmp));

            /* let the proc_thread_dispatcher() know about that */
            pthread_cond_broadcast(&kf_data->wait_cond);
        }
    }

    return (NULL);
}

/**
 *  Thread in charge to care about all process events.
 */
void *
proc_thread_dispatcher(void *arg) {
    struct filter *filt = arg;
    struct evfilt_data *kf_data = filt->kf_data;
    struct kproc_info *kp, *tmp;
    struct knote *kn;
    sigset_t sigmask;
    uint64_t counter = 1;

    dbg_printf("tid=%ld instances=%d - Process dispatcher thread started", syscall(SYS_gettid), proc_filter_instances);

    assert(proc_filter_instances == 1);

    /* Block all signals */
    sigfillset (&sigmask);
    pthread_sigmask(SIG_BLOCK, &sigmask, NULL);

    /* Catch any Ctrl-C and try to finalize the thread */
    signal(SIGINT, &proc_thread_on_sigint);
    siginterrupt(SIGINT, true);

    proc_thread_dispatcher_started = true;

    while (!need_exit) {
        if (pthread_cond_wait(&kf_data->wait_cond, &kf_data->wait_mtx) < 0) {
            dbg_perror("pthread_cond_wait");
            continue;
        }

        /* Scan the wait queue to see if anyone is interested */
        int i = 0;
        for (; i < MAX_PROC_BUFF; i++) {
            kp = &kf_data->proc_buff[i];

            if (kp->parent_pid == 0) continue;

            //dbg_printf("Looking for proc_list[%p] (parent_pid=%d || child_pid=%d)", kp, kp->parent_pid, kp->child_pid);

            kn = knote_lookup(filt, kp->parent_pid);
            // if (!kn) {
            //     kn = knote_lookup(filt, kp->child_pid);
            // }

            if (kn) {
                /* Copy the data. Can't be mempcy() because we need the ->fd value */
                kn->kdata.kn_kproc->proc_event = kp->proc_event;
                kn->kdata.kn_kproc->parent_pid = kp->parent_pid;
                kn->kdata.kn_kproc->child_pid  = kp->child_pid;
                kn->kdata.kn_kproc->exit_code  = kp->exit_code;

                /* Now, dispatch the process event */
                dbg_printf("kn=%p: Dispatch proc_event=%s { parent_pid=%d child_pid=%d } over kn_kproc->fd=%d with { ident=%d }",
                    kn, GET_PROC_EVENT_NAME(kn->kdata.kn_kproc->proc_event), kn->kdata.kn_kproc->parent_pid,
                    kn->kdata.kn_kproc->child_pid, kn->kdata.kn_kproc->fd, (int)kn->kev.ident);

                if (eventfd_write(kn->kdata.kn_kproc->fd, 1) < 0) {
                    dbg_printf("kn=%p: Problems to sinalize the knote", kn);
                    kn->kev.flags = EV_ERROR;
                    kn->kev.data = errno;
                    continue;
                }

                kp->parent_pid = 0; /* Already consumed */
                //dbg_printf("Removing (parent_pid=%d || child_pid=%d)", kp->parent_pid, kp->child_pid);
            } else {
                //dbg_printf("No listener for (parent_pid=%d || child_pid=%d)", kp->parent_pid, kp->child_pid);
            }
        }
    }

    return NULL;
}

/* filter operations */
int
evfilt_proc_filter_init(struct filter *filt)
{
    struct evfilt_data *kf_data;

    if (proc_filter_instances > 0) {
        proc_filter_instances++;
        dbg_printf("The EVFILT_PROC is already initialized with instances=%d", proc_filter_instances);
        return (0);
    }

    assert(proc_filter_instances == 0);
    proc_filter_instances++;

    dbg_printf("Initializing EVFILT_PROC instances=%d setup", proc_filter_instances);

    // libforkmonitor_init();

    if ((kf_data = calloc(1, sizeof(*kf_data))) == NULL) {
        return (-1);
    }

    filt->kf_data = kf_data;

    if (pthread_mutex_init(&kf_data->wait_mtx, NULL) < 0) {
        dbg_perror("pthread_mutex_init(3)");
        goto error;
    }

    if (pthread_cond_init(&kf_data->wait_cond, NULL) < 0) {
        dbg_perror("pthread_cond_init(3)");
        pthread_mutex_destroy(&kf_data->wait_mtx);
        goto error;
    }

    if (pthread_create(&kf_data->wthr_dispatcher_id, NULL, proc_thread_dispatcher, filt) != 0) {
        dbg_perror("pthread_create(3)");
        goto error;
    }

    if ((filt->kf_data->nl_fd = nl_init()) < 0) {
        dbg_perror("netlink nl_init()");
        goto error;
    }

    if (pthread_create(&kf_data->wthr_observer_id, NULL, proc_thread_observer, filt) != 0) {
        dbg_perror("pthread_create(3)");
        goto error;
    }

    /**
     * We need that to complete the 
     */
    while(!proc_thread_observer_started || !proc_thread_dispatcher_started);

    return (0);

error:
    if (filt->kf_data) {
        close(filt->kf_data->nl_fd);
        free(filt->kf_data);
        filt->kf_data = NULL;
    }

    return (-1);
}

void
evfilt_proc_filter_destroy(struct filter *filt) {
    struct evfilt_data *kf_data = filt->kf_data;
    void *thread_res = NULL;

    if (proc_filter_instances > 0) {
        dbg_printf("There EVFILT_PROC still running with instances=%d, It'll released soon.", proc_filter_instances);
        proc_filter_instances--;
        return;
    }

    dbg_printf("Releasing EVFILT_PROC setup proc_filter_instances=%d", proc_filter_instances);

    assert(proc_filter_instances == 0);

    if (pthread_cond_destroy(&kf_data->wait_cond) < 0) {
        dbg_perror("pthread_cond_destroy(3)");
    }

    if (pthread_mutex_destroy(&kf_data->wait_mtx) < 0) {
        dbg_perror("pthread_mutex_destroy(3)");
    }

    if (filt->kf_pfd >= 0) {
        close(filt->kf_pfd);
        filt->kf_pfd = -1;
    }

    free(kf_data);
    kf_data = NULL;
}

int
evfilt_proc_filter_copyout(struct kevent *dst, struct knote *src, void *ptr)
{
    struct kproc_info *kp = src->kdata.kn_kproc;
    struct epoll_event * const ev = (struct epoll_event *) ptr;
    struct knote *kn = ev->data.ptr;

    memcpy(dst, &src->kev, sizeof(*dst));

    dbg_printf("epoll_ev=%s", epoll_event_dump(ev));

    /**
     * Care about the EV_*
     */

    /* 1. EV_DISPATCH/EV_ONESHOT: handled in evfilt_proc_knote_create() */

    /*
     * 2. EV_CLEAR: Automatically set.
     * https://github.com/freebsd/freebsd/blob/release/12.1.0/sys/kern/kern_event.c#L435
     */
    dst->flags |= EV_CLEAR;
    if (src->kev.flags & EV_CLEAR) {
        src->kev.fflags &= ~NOTE_TRIGGER;
    }

    /* NOTE: True on FreeBSD but not consistent behavior with other filters. */
    if (src->kev.flags & EV_ADD) {
        dst->flags &= ~EV_ADD;
    }
    
    /* Do the magic */
    if (kp->proc_event == PROC_EVENT_FORK && (src->kev.fflags & NOTE_FORK)) {
        dbg_printf("NOTE_FORK: Process %d forked -> child %d PID", kp->parent_pid, kp->child_pid);
        dst->fflags = NOTE_FORK;
        dst->data = 0;
        dst->ident = kp->parent_pid;
    } else if (kp->proc_event == PROC_EVENT_EXEC && (src->kev.fflags & NOTE_EXEC)) {
        dbg_printf("NOTE_EXEC: Process %d executed %d PID", kp->parent_pid, kp->child_pid);

        dst->fflags = NOTE_EXEC;
        dst->flags |= EV_EOF;
    } else if (kp->proc_event == PROC_EVENT_EXIT && (src->kev.fflags & (NOTE_EXIT | NOTE_EXITSTATUS | NOTE_SIGNAL))) {
        dbg_printf("%s", proc_status_dump(kp->parent_pid, kp->exit_code));

        dst->fflags = NOTE_EXIT;
        dst->flags |= (EV_EOF | EV_ONESHOT); /* Good enough. the knote is done. */

        if ((src->kev.fflags & NOTE_EXITSTATUS) && WIFEXITED(kp->exit_code)) {
            dst->fflags |= NOTE_EXITSTATUS;
            dst->data = WEXITSTATUS(kp->exit_code);
        } else if ((src->kev.fflags & NOTE_SIGNAL) && WIFSIGNALED(kp->exit_code)) {
            dst->fflags |= NOTE_SIGNAL;
            dst->data = WTERMSIG(kp->exit_code);
        } else {
            dst->data = 0; /* Same as FreeBSD */
        }
    }

    return (0);
}

/* knote operations */
int
evfilt_proc_knote_create(struct filter *filt, struct knote *kn)
{
    int fd;
    int events;

    assert (kn->kdata.kn_kproc == NULL);

    kn->kdata.kn_kproc = calloc(1, sizeof(struct kproc_info));
    if (!kn->kdata.kn_kproc) {
        dbg_perror("calloc");
        return (-1);
    }

    if ((fd = eventfd(0, 0)) < 0) {
        dbg_perror("eventfd(2)");
    error:
        if (fd >= 0) close(fd);
        if (kn->kdata.kn_kproc) free(kn->kdata.kn_kproc);

        return (-1);
    }

    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        dbg_perror("fcntl(2)");
        goto error;
    }

    dbg_printf("kn=%p: ident=%d fd=%d epoll_fd=%d - created",
             kn, (int)kn->kev.ident, fd, filter_epoll_fd(filt));

    /*
     * For EV_ONESHOT, EV_DISPATCH we rely on common code
     * disabling/deleting the event after it's fired once.
     *
     * See this SO post for details:
     * https://stackoverflow.com/questions/59517961/how-should-i-use-epoll-to-read-and-write-from-the-same-fd
     */
    events = EPOLLIN;
    if (kn->kev.flags & (EV_ONESHOT | EV_DISPATCH)) {
        events |= EPOLLONESHOT;
    }

    KN_UDATA(kn);   /* populate this knote's kn_udata field */
    if (epoll_ctl(filter_epoll_fd(filt), EPOLL_CTL_ADD, fd, EPOLL_EV_KN(events, kn)) < 0) {
        dbg_perror("epoll_ctl(2)");
        goto error;
    }

    kn->kdata.kn_kproc->fd = fd;

    return (0);
}

int
evfilt_proc_knote_modify(UNUSED struct filter *filt, UNUSED struct knote *kn, UNUSED const struct kevent *kev)
{
    return (0); /* STUB */
}

int
evfilt_proc_knote_delete(struct filter *filt, struct knote *kn)
{
    int ret = (0);

    assert(kn->kdata.kn_kproc != NULL);
    assert(kn->kdata.kn_kproc->fd >= 0);

    dbg_printf("kn=%p: fd=%d epoll_fd=%d - deleted", kn, kn->kdata.kn_kproc->fd, filter_epoll_fd(filt));

    if (kn->kdata.kn_kproc->fd < 0) {
        goto out;
    }

    if (epoll_ctl(filter_epoll_fd(filt), EPOLL_CTL_DEL, kn->kdata.kn_kproc->fd, NULL) < 0) {
        dbg_perror("epoll_ctl(2)");
        ret = -1;
    }

    close(kn->kdata.kn_kproc->fd);

out:
    if (kn->kdata.kn_kproc) {
        free(kn->kdata.kn_kproc);
        kn->kdata.kn_kproc = NULL;
    }

    return ret;
}

int
evfilt_proc_knote_enable(UNUSED struct filter *filt, UNUSED struct knote *kn)
{
    return (0); /* STUB */
}

int
evfilt_proc_knote_disable(UNUSED struct filter *filt, UNUSED struct knote *kn)
{
    return (0); /* STUB */
}

const struct filter evfilt_proc = {
    .kf_id      = EVFILT_PROC,
    .kf_init    = evfilt_proc_filter_init,
    .kf_destroy = evfilt_proc_filter_destroy,
    .kf_copyout = evfilt_proc_filter_copyout,
    .kn_create  = evfilt_proc_knote_create,
    .kn_modify  = evfilt_proc_knote_modify,
    .kn_delete  = evfilt_proc_knote_delete,
    .kn_enable  = evfilt_proc_knote_enable,
    .kn_disable = evfilt_proc_knote_disable,
};
