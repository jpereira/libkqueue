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

#include "sys/event.h"
#include "private.h"

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
    enum what {      // <! Process event. e.g: FORK/EXEC/EXIT
        PROC_EVENT_NONE = 0x00000000,
        PROC_EVENT_FORK = 0x00000001,
        PROC_EVENT_EXEC = 0x00000002,
        PROC_EVENT_EXIT = 0x00000004
    } proc_event;
    pid_t parent_pid;  // <! Parent Process Id.
    int   exit_code;   // <! Exit status code.
    int   exit_signal; // <! Exit due to received a signal.
    int   fd;          // <! epoll_ctl(ADD) file descriptor.
};

/**
 * Thread monitor data struct
 */
struct evfilt_data {
    pthread_t        wthr_id;
    pthread_cond_t   wait_cond;
    pthread_mutex_t  wait_mtx;
    pthread_cond_t   wait_end;
    bool             need_exit;
};

#ifndef NDEBUG

/* Only the events needed */
#define GET_PROC_EVENT_NAME(x)  ((x == PROC_EVENT_FORK) ? "FORK" : \
                                 (x == PROC_EVENT_EXEC) ? "EXEC" : \
                                 (x == PROC_EVENT_EXIT) ? "EXIT" : "Unknown")
static int proc_filter_instances = 0;

static const char *
proc_status_dump(pid_t pid, int status) {
    static char buf[128];

    if (WIFEXITED(status)) {
        snprintf(buf, sizeof(buf), "(NOTE_EXIT|NOTE_EXITSTATUS): Process %d exited with status %d.", pid, WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        snprintf(buf, sizeof(buf), "(NOTE_EXIT|NOTE_SIGNAL): Process %d killed by signal %d.", pid, WTERMSIG(status));
    } else {
        snprintf(buf, sizeof(buf), "(NOTE_EXIT): Process %d terminated.", pid);
    }

    return buf;
}
#else
#define proc_status_dump(pid, status)
#endif

/**
 *  Thread in charge to know if the process EXITED or EXITED with SIGNAL.
 */
static void *
proc_thread_observer_pids(void *arg) {
    struct filter *filt = arg;
    struct knote *kn;
    sigset_t blockMask;
    pid_t parent_pid;
    int exit_code;

    dbg_printf("filt=%p: tid=%ld instances=%d - Process dispatcher thread started",
        filt, syscall(SYS_gettid), proc_filter_instances);

    /* Block all signals */
    sigfillset (&blockMask);
    sigdelset(&blockMask, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &blockMask, NULL);

    while (!filt->kf_data->need_exit) {
        parent_pid = waitpid(P_ALL, &exit_code, WNOHANG);
        if (parent_pid <= 0) {
            if (errno == ECHILD) {
                usleep(100);
                continue;
            }
            dbg_perror("waitpid");
            return NULL;
        }

        pthread_mutex_lock(&filt->kf_data->wait_mtx);
        /* Scan the wait queue to see if anyone is interested */
        kn = knote_lookup(filt, parent_pid);
        if (kn) {
            kn->kdata.kn_kproc->proc_event = PROC_EVENT_EXIT;
            kn->kdata.kn_kproc->parent_pid = parent_pid;
            kn->kdata.kn_kproc->exit_code  = exit_code;

            /* Now, dispatch the process event */
            dbg_printf("kn=%p: Dispatch proc_event=%s { parent_pid=%d, exit_code=%d } over kn_kproc->fd=%d with { ident=%d }",
                kn, GET_PROC_EVENT_NAME(kn->kdata.kn_kproc->proc_event), kn->kdata.kn_kproc->parent_pid,
                kn->kdata.kn_kproc->exit_code, kn->kdata.kn_kproc->fd, (int)kn->kev.ident);

            if (eventfd_write(kn->kdata.kn_kproc->fd, 1) < 0) {
                dbg_printf("kn=%p: Problems to sinalize the knote", kn);
                kn->kev.flags = EV_ERROR;
                kn->kev.data = errno;
            }
        }
        pthread_mutex_unlock(&filt->kf_data->wait_mtx);
    }

    pthread_cond_signal(&filt->kf_data->wait_end);

    return NULL;
}

/* filter operations */
int
evfilt_proc_filter_init(struct filter *filt)
{
    struct evfilt_data *kf_data;

    dbg_printf("filt=%p: Initializing EVFILT_PROC instances=%d setup", filt, proc_filter_instances++);

    if ((kf_data = calloc(1, sizeof(struct evfilt_data))) == NULL) {
        return (-1);
    }

    if (pthread_mutex_init(&kf_data->wait_mtx, NULL) < 0) {
        dbg_perror("pthread_mutex_init(3)");
        goto error;
    }

    if (pthread_cond_init(&kf_data->wait_cond, NULL) < 0) {
        dbg_perror("pthread_cond_init(3)");
        pthread_mutex_destroy(&kf_data->wait_mtx);
        goto error;
    }

    filt->kf_data = kf_data;

    if (pthread_create(&kf_data->wthr_id, NULL, proc_thread_observer_pids, filt) != 0) {
        dbg_perror("pthread_create(3)");
        goto error;
    }

    return (0);

error:
    if (kf_data) {
        pthread_cond_destroy(&kf_data->wait_cond);
        pthread_mutex_destroy(&kf_data->wait_mtx);
        free(kf_data);
        kf_data = NULL;
    }

    return (-1);
}

void
evfilt_proc_filter_destroy(struct filter *filt)
{
    struct evfilt_data *kf_data = filt->kf_data;

    dbg_printf("filt=%p: Releasing EVFILT_PROC setup instances=%d\n", filt, proc_filter_instances--);

    filt->kf_data->need_exit = true;
    if (pthread_cond_wait(&filt->kf_data->wait_end, &filt->kf_data->wait_mtx) != 0) {
        dbg_perror("pthread_cond_wait(3)");
    }

    if (pthread_cond_destroy(&kf_data->wait_cond) < 0) {
        dbg_perror("pthread_cond_destroy(3)");
    }

    if (pthread_mutex_destroy(&kf_data->wait_mtx) < 0) {
        dbg_perror("pthread_mutex_destroy(3)");
    }

    free(filt->kf_data);
    filt->kf_data = NULL;
}

int
evfilt_proc_filter_copyout(struct kevent *dst, struct knote *src, void *ptr)
{
    struct kproc_info *kp = src->kdata.kn_kproc;

    memcpy(dst, &src->kev, sizeof(*dst));

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
    if (kp->proc_event == PROC_EVENT_EXIT && (src->kev.fflags & (NOTE_EXIT | NOTE_EXITSTATUS | NOTE_SIGNAL))) {
        dbg_printf("%s", proc_status_dump(kp->parent_pid, kp->exit_code));

        dst->flags |= (EV_EOF | EV_ONESHOT); /* Good enough. the knote is done. */
        dst->fflags = NOTE_EXIT;

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
#if 0
    else if (kp->proc_event == PROC_EVENT_FORK && (src->kev.fflags & NOTE_FORK)) {
        dbg_printf("NOTE_FORK: Process %d forked -> child %d PID", kp->parent_pid, kp->child_pid);
        dst->fflags = NOTE_FORK;
        dst->data = 0;
        dst->ident = kp->parent_pid;
    } else if (kp->proc_event == PROC_EVENT_EXEC && (src->kev.fflags & NOTE_EXEC)) {
        dbg_printf("NOTE_EXEC: Process %d executed %d PID", kp->parent_pid, kp->child_pid);

        dst->fflags = NOTE_EXEC;
        dst->flags |= EV_EOF;
    }
#else
    else {
        dst->fflags &= ~(NOTE_EXIT | NOTE_EXITSTATUS | NOTE_SIGNAL);
        dst->flags = EV_ERROR;
        dst->data = ENOSYS; /* Function not implemented */
    }
#endif

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
