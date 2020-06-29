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

/**
 * @File: src/linux/proc.c
 * @Author: Jorge Pereira <jpereira@freeradius.org>
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>

#include "sys/event.h"
#include "private.h"

/**
 *  EVFILT_PROC      Takes the process ID to monitor as the identifier and
 *                   the events to watch for in fflags, and returns when the
 *                   process performs one or more of the requested events.
 *                   If a process can normally see another process, it can
 *                   attach an event to it.  The events to monitor are:
 *
 *                   NOTE_EXIT    The process has exited.
 *
 *                   NOTE_EXITSTATUS
 *                                The process has exited and its exit status
 *                                is in filter specific data. Valid only on
 *                                child processes and to be used along with
 *                                NOTE_EXIT.
 *
 *                   NOTE_FORK    The process created a child process via
 *                                fork(2) or similar call.
 *
 *                   NOTE_EXEC    The process executed a new process via
 *                                execve(2) or similar call.
 *
 *                   NOTE_SIGNAL  The process was sent a signal. Status can
 *                                be checked via waitpid(2) or similar call.
 *
 *                   NOTE_REAP    The process was reaped by the parent via
 *                                wait(2) or similar call. Deprecated, use
 *                                NOTE_EXIT.
 *
 *                   On return, fflags contains the events which triggered
 *                   the filter.
 */

#ifndef NDEBUG
static const char *
proc_status_dump(pid_t pid, int status) {
    static __thread char buf[128];

    if (WIFEXITED(status)) {
         snprintf(buf, sizeof(buf), "Process %d exited with status %d.", pid, WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
         snprintf(buf, sizeof(buf), "Process %d killed by signal %d.", pid, WTERMSIG(status));
    } else {
         snprintf(buf, sizeof(buf), "Process %d terminated.", pid);
    }

    return buf;
}

static const char *
nl_proc_event_dump(struct proc_event *pe) {
    static __thread char buf[256];

    assert(pe != NULL);

    switch (pe->what) {
        case PROC_EVENT_NONE:
            snprintf(buf, sizeof(buf), "proc_event=%p: PROC_EVENT_NONE { NULL }", pe);
            break;
        case PROC_EVENT_FORK:
            snprintf(buf, sizeof(buf), "proc_event=%p: PROC_EVENT_FORK { parent tid=%d pid=%d -> child tid=%d pid=%d }",
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
#else
#define nl_proc_event_dump(pe)
#define proc_status_dump(pid, status)
#endif

/* Check if is a valid PID */
static bool
pid_is_exist(pid_t pid)
{
    return (kill(pid, 0) == 0);
}

static int
nl_connect()
{
    int nl_sock;
    struct sockaddr_nl sa_nl = {
        .nl_family = AF_NETLINK,
        .nl_groups = CN_IDX_PROC,
        .nl_pid = getpid()
    };

    nl_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (nl_sock == -1) {
        dbg_perror("netlink socket(2)");
        return -1;
    }

    if (fcntl(nl_sock, F_SETFL, fcntl(nl_sock, F_GETFL) | O_NONBLOCK) < 0) {
        dbg_perror("netlink fcntl(2)");
    error:
        close(nl_sock);
        return -1;
    }

    if (bind(nl_sock, (struct sockaddr *)&sa_nl, sizeof(sa_nl)) < 0) {
        dbg_perror("netlink bind(2)");
        goto error;
    }

    return nl_sock;
}

static int
nl_set_listen(int nl_sock)
{
    struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr nl_hdr;
        struct __attribute__ ((__packed__)) {
            struct cn_msg cn_msg;
            enum proc_cn_mcast_op cn_mcast;
        };
    } nlcn_msg = {
        .nl_hdr.nlmsg_len = sizeof(nlcn_msg),
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

    if (send(nl_sock, &nlcn_msg, sizeof(nlcn_msg), 0) < 0) {
        dbg_perror("netlink send(2)");
        return -1;
    }

    return 0;
}

static sig_atomic_t __thread need_exit = false;

static void
on_sigint(UNUSED int unused)
{
    need_exit = true;
}

int
evfilt_proc_copyout(struct kevent *dst, struct knote *src, void *ptr)
{
    struct epoll_event *const ev = (struct epoll_event *) ptr;
    struct {
        struct nlmsghdr nl_hdr;
        struct __attribute__ ((__packed__)) {
            struct cn_msg cn_msg;
            struct proc_event proc_ev;
        };
    } nlcn_msg;
    pid_t pid = (pid_t)src->kev.ident;
    int nevents = 0;

    signal(SIGINT, &on_sigint);
    siginterrupt(SIGINT, true);

    dbg_printf("procfd=%d pid=%d epoll_event=%s", src->kdata.kn_procfd, pid, epoll_event_dump(ev));

    memcpy(dst, &src->kev, sizeof(*dst));
    dst->data = 0;
    dst->fflags = 0;

    while (!need_exit) {
        int rc;

        memset(&nlcn_msg, 0, sizeof(nlcn_msg));

        /* Let's avoid look for something that no longer exist */
        if (!pid_is_exist(pid)) {
            dbg_printf("pid=%d (No such process)", pid);
            return (0);
        }

        rc = recv(src->kdata.kn_procfd, &nlcn_msg, sizeof(nlcn_msg), 0);
        if (rc == 0) {  /* shutdown? */
            dbg_printf("netlink recv: shutdown");
            return (0);
        } else if (rc < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* It's not *really* ready for recv; wait until it is. */
                continue;
            }

            dbg_perror("netlink recv");
            return (-1);
        }

        if (nlcn_msg.proc_ev.what == PROC_EVENT_NONE) {
            continue;
        }

        /**
         * Just to shut up the compiler warnings about
         * copy & assigment among __packed__ variables.
         */
        void *_pe = &nlcn_msg.proc_ev;
        struct proc_event *pe = _pe;

        /**
         * The nl_proc_event_dump() is very verbose.
         * Only useful to enable during troubleshooting.
         */
#if 0
        dbg_printf("%s", nl_proc_event_dump(pe));
#endif

        if (src->kev.fflags & NOTE_FORK) {
            if (!(pe->what == PROC_EVENT_FORK && pe->event_data.fork.parent_pid == pid)) {
                continue;
            }

            dst->fflags |= NOTE_FORK;
            dbg_printf("proc_event=%p: Process %d forked -> child { pid=%d, tgid=%d }",
                pe, pid, pe->event_data.fork.child_pid, pe->event_data.fork.child_tgid);
            nevents++;
            break;
        } else if (src->kev.fflags & NOTE_EXEC) {
            if (!(pe->what == PROC_EVENT_EXEC && pe->event_data.exec.process_pid == pid)) {
                continue;
            }

            dst->fflags |= NOTE_EXEC;
            dbg_printf("proc_event=%p: Process %d executed the process { pid=%d, tgid=%d }",
                pe, pid, pe->event_data.exec.process_pid, pe->event_data.exec.process_tgid);
            nevents++;
            break;
        } else if (src->kev.fflags & (NOTE_EXIT | NOTE_EXITSTATUS | NOTE_SIGNAL)) {
            int exit_code;

            if (!(pe->what == PROC_EVENT_EXIT && pe->event_data.exit.process_pid == pid)) {
                continue;
            }

            dst->fflags |= NOTE_EXIT;
            exit_code = pe->event_data.exit.exit_code;

            if ((src->kev.fflags & NOTE_EXITSTATUS) && WIFEXITED(exit_code)) {
                dst->data = WEXITSTATUS(exit_code);
                dst->fflags |= NOTE_EXITSTATUS;
            } else if ((src->kev.fflags & NOTE_SIGNAL) && WIFSIGNALED(exit_code)) {
                dst->data = WTERMSIG(exit_code);
                dst->fflags |= NOTE_SIGNAL;
            }

            dbg_printf("proc_event=%p: %s", pe, proc_status_dump(pid, exit_code));
            nevents++;
            break;
        } else {
            dbg_printf("proc_event=%p: Error: Unknown fflags=%#x", pe, src->kev.fflags);
            return (-1);
        }
    }

    return (nevents);
}

int
evfilt_proc_knote_create(struct filter *filt, struct knote *kn)
{
    pid_t pid = (pid_t)kn->kev.ident;
    int nl_fd;
    int events;

    kn->kdata.kn_procfd = -1;

    if (!pid_is_exist(pid)) {
        dbg_printf("pid=%d (No such process)", pid);
        return -1;
    }

    if ((nl_fd = nl_connect()) < 0) {
        dbg_perror("fd_used=%u fd_max=%u nl_connect()", get_fd_used(), get_fd_limit());
        return (-1);
    }

    dbg_printf("epollfd=%d pid=%d nl_fd=%d created", filter_epoll_fd(filt), pid, nl_fd);

    if (nl_set_listen(nl_fd) < 0) {
        dbg_perror("fd_used=%u fd_max=%u nl_set_listen()", get_fd_used(), get_fd_limit());
    error:
        (void)close(nl_fd);
        return (-1);
    }

    events = (EPOLLIN | EPOLLET | EPOLLRDHUP);
    if (kn->kev.flags & (EV_ONESHOT | EV_DISPATCH)) {
        events |= EPOLLONESHOT;
    }
    kn->kdata.kn_procfd = nl_fd;

    KN_UDATA(kn);   /* populate this knote's kn_udata field */

    /* Add the NetLink fd to the kqueue's epoll descriptor set */
    if (epoll_ctl(filter_epoll_fd(filt), EPOLL_CTL_ADD, nl_fd, EPOLL_EV_KN(events, kn)) < 0) {
        dbg_perror("epoll_ctl(2)");
        goto error;
    }

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
    int pid = (pid_t)kn->kev.ident;
    int nl_fd = kn->kdata.kn_procfd;

    dbg_printf("epollfd=%d pid=%d nl_fd=%d", filter_epoll_fd(filt), pid, nl_fd);

    if (nl_fd < 0) {
        return (0);
    }

    if (epoll_ctl(filter_epoll_fd(filt), EPOLL_CTL_DEL, nl_fd, NULL) < 0) {
        dbg_perror("epoll_ctl(2)");
        return (-1);
    }

    (void) close(nl_fd);
    kn->kdata.kn_procfd = -1;

    return (0);
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
    .kf_copyout = evfilt_proc_copyout,
    .kn_create  = evfilt_proc_knote_create,
    .kn_modify  = evfilt_proc_knote_modify,
    .kn_delete  = evfilt_proc_knote_delete,
    .kn_enable  = evfilt_proc_knote_enable,
    .kn_disable = evfilt_proc_knote_disable,
};
