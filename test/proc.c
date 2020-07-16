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

#include "common.h"

/**
 * The "NOTE_TRACK" support was properly deprecated on OSX > 10.5
 * as can be seen in:
 *
 * http://www.openradar.appspot.com/7129001
 * http://newosxbook.com/src.jl?tree=xnu&file=/bsd/sys/event.h
 * CVE-ID: CVE-2006-6127
 *  ~> https://lists.apple.com/archives/security-announce/2007/Nov/msg00002.html
 */
#ifdef __APPLE__
#  include <AvailabilityMacros.h>
#  if (MAC_OS_X_VERSION_MIN_REQUIRED > MAC_OS_X_VERSION_10_5)
#    define OSX_DEPRECATED_NOTE_TRACK
#  endif
#endif

static int sigusr1_caught = 0;
static int sleep_time = 0;

static void
sig_handler(int signum)
{
    sigusr1_caught = 1;
}

static void
test_kevent_proc_add_and_delete(struct test_context *ctx)
{
    struct kevent kev;
    pid_t pid;

    /* Create a child that waits to be killed and then exits */
    pid = fork();
    if (pid == 0) {
        struct stat s;

        usleep (500); // TODO: It should be removed and fixed.

        if (fstat(ctx->kqfd, &s) != -1) {
            errx(1, "kqueue inherited across fork! (%s() at %s:%d)",
                __func__, __FILE__, __LINE__);
        }

        pause();
        _exit(2);
    }
    printf(" -- child created (pid %d)\n", (int) pid);

    printf(" -- kevent(EVFILT_PROC, EV_ADD)\n");
    test_no_kevents(ctx->kqfd);
    kevent_add(ctx->kqfd, &kev, pid, EVFILT_PROC, EV_ADD, 0, 0, NULL);
    test_no_kevents(ctx->kqfd);

    printf(" -- kevent(EVFILT_PROC, EV_DELETE)\n");
    test_no_kevents(ctx->kqfd);
    kevent_add(ctx->kqfd, &kev, pid, EVFILT_PROC, EV_DELETE, 0, 0, NULL);
    if (kill(pid, SIGKILL) < 0)
        err(1, "kill");
    sleep(1);
    test_no_kevents(ctx->kqfd);
}

static void
test_kevent_proc_note_exit_exitstatus(struct test_context *ctx)
{
    char test_id[128];
    struct kevent kev;
    pid_t pid;
    int pipe_fd[2];
    int total_childs = 5, i = 0;
    ssize_t result;

    test_no_kevents(ctx->kqfd);

    if (pipe(pipe_fd)) {
        errx(1, "pipe (parent) failed! (%s() at %s:%d)",
            __func__, __FILE__, __LINE__);
    }

    test_no_kevents(ctx->kqfd);
    for (i=0; i < total_childs; i++) {
        /* Create a child to track. */
        pid = fork();

        if (pid == 0) { /* Child */
            int exit_code = 66 + i;
            /*
             * Give the parent a chance to start tracking us.
             */
            result = read(pipe_fd[0], test_id, 1);
            if (result != 1) {
                errx(1, "read from pipe in child failed! (ret %zd) (%s() at %s:%d)",
                    result, __func__, __FILE__, __LINE__);
            }

            sleep_time += i;
            printf("Child waiting for %ds, exit_code=%d\n", sleep_time, exit_code);
            if (sleep_time) sleep(sleep_time);

            _exit(exit_code); /* We need _exit() instead of exit() to don't trigger testing_atexit() */
        } else if (pid == -1) { /* Error */
            errx(1, "fork (child) failed! (%s() at %s:%d)",
                __func__, __FILE__, __LINE__);
        }

        snprintf(test_id, sizeof(test_id),
                "[%d] kevent(EVFILT_PROC, pid=%d, NOTE_EXIT | NOTE_EXITSTATUS); sleep %d", i, pid, sleep_time);
        printf(" -- %s\n", test_id);

        printf(" -- child created (pid %d)\n", (int) pid);

        kevent_add(ctx->kqfd,
                    &kev,
                    pid,
                    EVFILT_PROC,
                    EV_ADD,
                    NOTE_EXIT | NOTE_EXITSTATUS,
                    0, NULL);

        printf(" -- tracking child (pid %d)\n", (int) pid);

        /* Now that we're tracking the child, tell it to proceed. */
        result = write(pipe_fd[1], test_id, 1);
        if (result != 1) {
            errx(1, "write to pipe in parent failed! (ret %zd) (%s() at %s:%d)",
                result, __func__, __FILE__, __LINE__);
        }
    }

    {
        int child_exit = 0;
        int done = 0;
        char const *kev_str;

        while (!done)
        {
            int ret;
            int handled = 0;
            struct kevent buf = { 0, };
            struct kevent *kevp = &buf;
            struct timespec ts = {
                .tv_sec = 5,
                .tv_nsec = 0
            };

            printf("~> Waiting for %lds kevent_get_timeout()\n", ts.tv_sec);
            ret = kevent_get_timeout(kevp, ctx->kqfd, &ts);

            if (ret == 0) {
                done = 1;
            } else if (ret < 0) {
                if (kevp->flags & EV_ERROR) {
                    printf("!!! EV_ERROR: 'data' is errno=%d (%s)\n", (int)kevp->data, strerror((int)kevp->data));
                }
            } else {
                kev_str = kevent_to_str(kevp);
                printf(" -- Received kevent: %s\n", kev_str);

                if (kevp->fflags & (NOTE_EXIT | NOTE_EXITSTATUS)) {
                    // TODO: Save the pids of each fork() and compare here. 
                    ++child_exit;
                    ++handled;
                }

                if (!handled) {
                    errx(1, "Spurious kevent: %s", kevent_to_str(kevp));
                }
            }
        }

        /* Make sure all expected events were received. */
        if (child_exit == total_childs) {
            printf(" -- Received all expected events.\n");
        } else {
            errx(1, "########## Did not receive all expected events.\nchild_exit=%d",
                    child_exit);
        }
    }
}

static void
test_kevent_proc_fork_exit(struct test_context *ctx)
{
    char test_id[64];
    struct kevent kev;
    pid_t pid;
    int pipe_fd[2];
    ssize_t result;

    test_no_kevents(ctx->kqfd);

    if (pipe(pipe_fd)) {
        errx(1, "pipe (parent) failed! (%s() at %s:%d)",
            __func__, __FILE__, __LINE__);
    }

    /* Create a child to track. */
    pid = fork();

    snprintf(test_id, sizeof(test_id),
            "kevent(EVFILT_PROC, pid=%d, NOTE_EXEC | NOTE_EXIT | NOTE_FORK); sleep %d", pid, sleep_time);
    printf(" -- %s\n", test_id);

    if (pid == 0) { /* Child */
        pid_t grandchild = -1;

        /*
         * Give the parent a chance to start tracking us.
         */
        result = read(pipe_fd[0], test_id, 1);
        if (result != 1) {
            errx(1, "read from pipe in child failed! (ret %zd) (%s() at %s:%d)",
                result, __func__, __FILE__, __LINE__);
        }

        /*
         * Spawn a grandchild that will immediately exit. If the kernel has bug
         * 180385, the parent will see a kevent with both NOTE_CHILD and
         * NOTE_EXIT. If that bug is fixed, it will see two separate kevents
         * for those notes. Note that this triggers the conditions for
         * detecting the bug quite reliably on a 1 CPU system (or if the test
         * process is restricted to a single CPU), but may not trigger it on a
         * multi-CPU system.
         */
        grandchild = fork();
        if (grandchild == 0) { /* Grandchild */
            if (sleep_time) sleep(sleep_time);

            _exit(1); /* We need _exit() instead of exit() to don't trigger testing_atexit() */
        } else if (grandchild == -1) { /* Error */
            errx(1, "fork (grandchild) failed! (%s() at %s:%d)",
                __func__, __FILE__, __LINE__);
        }
        if (sleep_time) sleep(sleep_time);

        _exit(0); /* We need _exit() instead of exit() to don't trigger testing_atexit() */
    } else if (pid == -1) { /* Error */
        errx(1, "fork (child) failed! (%s() at %s:%d)",
            __func__, __FILE__, __LINE__);
    }

    printf(" -- child created (pid %d)\n", (int) pid);

    test_no_kevents(ctx->kqfd);
    kevent_add(ctx->kqfd,
                &kev,
                pid,
                EVFILT_PROC,
                EV_ADD | EV_ENABLE,
                NOTE_EXEC | NOTE_EXIT | NOTE_FORK,
                0, NULL);

    printf(" -- tracking child (pid %d)\n", (int) pid);

    /* Now that we're tracking the child, tell it to proceed. */
    result = write(pipe_fd[1], test_id, 1);
    if (result != 1) {
        errx(1, "write to pipe in parent failed! (ret %zd) (%s() at %s:%d)",
            result, __func__, __FILE__, __LINE__);
    }

    /*
     * Several events should be received:
     *  - NOTE_FORK (from child)
     *  - NOTE_EXIT (from child)
     *
     * The NOTE_FORK and NOTE_EXIT from the child could be combined into a
     * single event, but the NOTE_CHILD and NOTE_EXIT from the grandchild must
     * not be combined.
     *
     * The loop continues until no events are received within a 5 second
     * period, at which point it is assumed that no more will be coming. The
     * loop is deliberately designed to attempt to get events even after all
     * the expected ones are received in case some spurious events are
     * generated as well as the expected ones.
     */
    {
        int child_exit = 0;
        int child_fork = 0;
        int done = 0;
        char const *kev_str;

        while (!done)
        {
            int handled = 0;
            struct kevent buf = { 0, };
            struct kevent *kevp = &buf;
            struct timespec ts = {
                .tv_sec = 2,
                .tv_nsec = 0
            };

            printf("~> Waiting for kevent_get_timeout()\n");
            if (kevent_get_timeout(kevp, ctx->kqfd, &ts) == 0) {
                done = 1;
            } else {
                kev_str = kevent_to_str(kevp);
                printf(" -- Received kevent: %s\n", kev_str);

                if ((kevp->fflags & NOTE_CHILD) && (kevp->fflags & NOTE_EXIT)) {
                    errx(1, "NOTE_CHILD and NOTE_EXIT in same kevent: %s", kevent_to_str(kevp));
                }

                if (kevp->fflags & NOTE_EXIT) {
                    if ((kevp->ident == pid) && (!child_exit)) {
                        ++child_exit;
                        ++handled;
                    } else {
                        errx(1, "Spurious NOTE_EXIT: %s", kevent_to_str(kevp));
                    }
                }

                if (kevp->fflags & NOTE_FORK) {
                    if ((kevp->ident == pid) && (!child_fork)) {
                        ++child_fork;
                        ++handled;
                    } else {
                        errx(1, "Spurious NOTE_FORK: %s", kevent_to_str(kevp));
                    }
                }

                if (!handled) {
                    errx(1, "Spurious kevent: %s", kevent_to_str(kevp));
                }
            }
        }

        /* Make sure all expected events were received. */
        if (child_exit && child_fork) {
            printf(" -- Received all expected events.\n");
        } else {
            errx(1, "########## Did not receive all expected events.\nchild_exit=%d, child_fork=%d",
                    child_exit, child_fork);
        }
    }
}

#ifndef HAVENT_NOTE_TRACK
static void
test_kevent_proc_track(struct test_context *ctx)
{
    char test_id[64];
    struct kevent kev;
    pid_t pid;
    int pipe_fd[2];
    ssize_t result;

    test_no_kevents(ctx->kqfd);

    if (pipe(pipe_fd)) {
        errx(1, "pipe (parent) failed! (%s() at %s:%d)",
            __func__, __FILE__, __LINE__);
    }

    /* Create a child to track. */
    pid = fork();

    snprintf(test_id, sizeof(test_id),
            "kevent(EVFILT_PROC, pid=%d, NOTE_TRACK); sleep %d", pid, sleep_time);
    printf(" -- %s\n", test_id);

    if (pid == 0) { /* Child */
        pid_t grandchild = -1;

        /*
         * Give the parent a chance to start tracking us.
         */
        result = read(pipe_fd[0], test_id, 1);
        if (result != 1) {
            errx(1, "read from pipe in child failed! (ret %zd) (%s() at %s:%d)",
                result, __func__, __FILE__, __LINE__);
        }

        /*
         * Spawn a grandchild that will immediately exit. If the kernel has bug
         * 180385, the parent will see a kevent with both NOTE_CHILD and
         * NOTE_EXIT. If that bug is fixed, it will see two separate kevents
         * for those notes. Note that this triggers the conditions for
         * detecting the bug quite reliably on a 1 CPU system (or if the test
         * process is restricted to a single CPU), but may not trigger it on a
         * multi-CPU system.
         */
        grandchild = fork();
        if (grandchild == 0) { /* Grandchild */
            if (sleep_time) sleep(sleep_time);

            _exit(1); /* We need _exit() instead of exit() to don't trigger testing_atexit() */
        } else if (grandchild == -1) { /* Error */
            errx(1, "fork (grandchild) failed! (%s() at %s:%d)",
                __func__, __FILE__, __LINE__);
        } else { /* Child (Grandchild Parent) */
            printf(" -- grandchild created (pid %d)\n", (int) grandchild);
        }
        if (sleep_time) sleep(sleep_time);

        _exit(0); /* We need _exit() instead of exit() to don't trigger testing_atexit() */
    } else if (pid == -1) { /* Error */
        errx(1, "fork (child) failed! (%s() at %s:%d)",
            __func__, __FILE__, __LINE__);
    }

    printf(" -- child created (pid %d)\n", (int) pid);

    test_no_kevents(ctx->kqfd);
    kevent_add(ctx->kqfd,
                &kev,
                pid,
                EVFILT_PROC,
                EV_ADD | EV_ENABLE,
                NOTE_TRACK | NOTE_EXEC | NOTE_EXIT | NOTE_FORK,
                0, NULL);

    printf(" -- tracking child (pid %d)\n", (int) pid);

    /* Now that we're tracking the child, tell it to proceed. */
    result = write(pipe_fd[1], test_id, 1);
    if (result != 1) {
        errx(1, "write to pipe in parent failed! (ret %zd) (%s() at %s:%d)",
            result, __func__, __FILE__, __LINE__);
    }

    /*
     * Several events should be received:
     *  - NOTE_FORK (from child)
     *  - NOTE_CHILD (from grandchild)
     *  - NOTE_EXIT (from grandchild)
     *  - NOTE_EXIT (from child)
     *
     * The NOTE_FORK and NOTE_EXIT from the child could be combined into a
     * single event, but the NOTE_CHILD and NOTE_EXIT from the grandchild must
     * not be combined.
     *
     * The loop continues until no events are received within a 5 second
     * period, at which point it is assumed that no more will be coming. The
     * loop is deliberately designed to attempt to get events even after all
     * the expected ones are received in case some spurious events are
     * generated as well as the expected ones.
     */
    {
        int child_exit = 0;
        int child_fork = 0;
        int gchild_exit = 0;
        int gchild_note = 0;
        pid_t gchild_pid = -1;
        int done = 0;
        char const *kev_str;

        while (!done)
        {
            int handled = 0;
            struct kevent buf;
            struct kevent *kevp = &buf;
            struct timespec ts = {
                .tv_sec = 2,
                .tv_nsec = 0
            };

            // kevp->flags = EV_ADD | EV_ENABLE;
            // kevp->fflags = NOTE_TRACK | NOTE_EXEC | NOTE_EXIT | NOTE_FORK;

            printf("~> Waiting for kevent_get_timeout()\n");
            int ret = kevent_get_timeout(kevp, ctx->kqfd, &ts);

            if (ret == 0) {
                done = 1;
            } else {
                kev_str = kevent_to_str(kevp);
                printf(" -- Received kevent: %s\n", kev_str);

                if ((kevp->fflags & NOTE_CHILD) && (kevp->fflags & NOTE_EXIT)) {
                    errx(1, "NOTE_CHILD and NOTE_EXIT in same kevent: %s", kevent_to_str(kevp));
                }

                if (kevp->fflags & NOTE_CHILD) {
                    if (kevp->data == pid) {
                        if (!gchild_note) {
                            ++gchild_note;
                            gchild_pid = kevp->ident;
                            ++handled;
                        } else {
                            errx(1, "Spurious NOTE_CHILD: %s", kevent_to_str(kevp));
                        }
                    }
                }

                if (kevp->fflags & NOTE_EXIT) {
                    if ((kevp->ident == pid) && (!child_exit)) {
                        ++child_exit;
                        ++handled;
                    } else if ((kevp->ident == gchild_pid) && (!gchild_exit)) {
                        ++gchild_exit;
                        ++handled;
                    } else {
                        errx(1, "Spurious NOTE_EXIT: %s", kevent_to_str(kevp));
                    }
                }

                if (kevp->fflags & NOTE_FORK) {
                    //printf("evp->ident=%d == pid=%d child_fork=%d\n", kevp->ident, pid, child_fork);

                    if ((kevp->ident == pid) && (!child_fork)) {
                        ++child_fork;
                        ++handled;
                    } else {
                        errx(1, "Spurious NOTE_FORK: %s", kevent_to_str(kevp));
                    }
                }

                if (!handled) {
                    errx(1, "Spurious kevent: %s", kevent_to_str(kevp));
                }
            }
        }

        /* Make sure all expected events were received. */
        if (child_exit && child_fork && gchild_exit && gchild_note) {
            printf(" -- Received all expected events.\n");
        } else {
            errx(1, "########## Did not receive all expected events.\nchild_exit=%d, child_fork=%d, gchild_exit=%d, gchild_note=%d",
                    child_exit, child_fork, gchild_exit, gchild_note);
        }
    }
}
#endif

#ifdef TODO
void
test_kevent_signal_disable(struct test_context *ctx)
{
    const char *test_id = "kevent(EVFILT_SIGNAL, EV_DISABLE)";
    struct kevent kev;

    test_begin(test_id);

    EV_SET(&kev, SIGUSR1, EVFILT_SIGNAL, EV_DISABLE, 0, 0, NULL);
    if (kevent(kqfd, &kev, 1, NULL, 0, NULL) < 0)
        die("%s", test_id);

    /* Block SIGUSR1, then send it to ourselves */
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1)
        die("sigprocmask");
    if (kill(getpid(), SIGKILL) < 0)
        die("kill");

    test_no_kevents();

    success();
}

void
test_kevent_signal_enable(struct test_context *ctx)
{
    const char *test_id = "kevent(EVFILT_SIGNAL, EV_ENABLE)";
    struct kevent kev;

    test_begin(test_id);

    EV_SET(&kev, SIGUSR1, EVFILT_SIGNAL, EV_ENABLE, 0, 0, NULL);
    if (kevent(kqfd, &kev, 1, NULL, 0, NULL) < 0)
        die("%s", test_id);

    /* Block SIGUSR1, then send it to ourselves */
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1)
        die("sigprocmask");
    if (kill(getpid(), SIGUSR1) < 0)
        die("kill");

    kev.flags = EV_ADD | EV_CLEAR;
#if LIBKQUEUE
    kev.data = 1; /* WORKAROUND */
#else
    kev.data = 2; // one extra time from test_kevent_signal_disable()
#endif
    kevent_cmp(&kev, kevent_get(kqfd));

    /* Delete the watch */
    kev.flags = EV_DELETE;
    if (kevent(kqfd, &kev, 1, NULL, 0, NULL) < 0)
        die("%s", test_id);

    success();
}

void
test_kevent_signal_del(struct test_context *ctx)
{
    const char *test_id = "kevent(EVFILT_SIGNAL, EV_DELETE)";
    struct kevent kev;

    test_begin(test_id);

    /* Delete the kevent */
    EV_SET(&kev, SIGUSR1, EVFILT_SIGNAL, EV_DELETE, 0, 0, NULL);
    if (kevent(kqfd, &kev, 1, NULL, 0, NULL) < 0)
        die("%s", test_id);

    /* Block SIGUSR1, then send it to ourselves */
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1)
        die("sigprocmask");
    if (kill(getpid(), SIGUSR1) < 0)
        die("kill");

    test_no_kevents();
    success();
}

void
test_kevent_signal_oneshot(struct test_context *ctx)
{
    const char *test_id = "kevent(EVFILT_SIGNAL, EV_ONESHOT)";
    struct kevent kev;

    test_begin(test_id);

    EV_SET(&kev, SIGUSR1, EVFILT_SIGNAL, EV_ADD | EV_ONESHOT, 0, 0, NULL);
    if (kevent(kqfd, &kev, 1, NULL, 0, NULL) < 0)
        die("%s", test_id);

    /* Block SIGUSR1, then send it to ourselves */
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1)
        die("sigprocmask");
    if (kill(getpid(), SIGUSR1) < 0)
        die("kill");

    kev.flags |= EV_CLEAR;
    kev.data = 1;
    kevent_cmp(&kev, kevent_get(kqfd));

    /* Send another one and make sure we get no events */
    if (kill(getpid(), SIGUSR1) < 0)
        die("kill");
    test_no_kevents();

    success();
}
#endif

void
test_evfilt_proc(struct test_context *ctx)
{
    signal(SIGUSR1, sig_handler);

    test(kevent_proc_add_and_delete, ctx);

    // NOTE_EXIT | NOTE_EXITSTATUS
    sleep_time = 0;
    test(kevent_proc_note_exit_exitstatus, ctx);

    sleep_time = 1;
    test(kevent_proc_note_exit_exitstatus, ctx);

    /*
     * The below tests are not supported on Linux (yet)
     *
     * - NOTE_FORK
     * - NOTE_TRACK
     * - NOTE_EXEC
     */
#if defined(__linux__)
    printf("WARNING: Linux doesn't support EVFILT_PROC & (NOTE_FORK | NOTE_TRACK | NOTE_EXEC)\n");
#else
    sleep_time = 0;
    test(kevent_proc_fork_exit, ctx);

    sleep_time = 1;
    test(kevent_proc_fork_exit, ctx);

#ifdef OSX_DEPRECATED_NOTE_TRACK
    printf("WARNING: OSX Doesn't support 'NOTE_TRACK', so ignoring proc_track() tests\n");
#else
    sleep_time = 0;
    test(kevent_proc_track, ctx);

    sleep_time = 1;
    test(kevent_proc_track, ctx);
#endif

#endif /* __linux__ */

    signal(SIGUSR1, SIG_DFL);

#if TODO
    test_kevent_signal_add();
    test_kevent_signal_del();
    test_kevent_signal_get();
    test_kevent_signal_disable();
    test_kevent_signal_enable();
    test_kevent_signal_oneshot();
#endif
}
