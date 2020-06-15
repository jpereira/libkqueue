/*
 * Copyright (c) 2020 Jorge Pereira <jpereira@freeradius.org>
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

#include <stdio.h>

#include "private.h"

void
__kqueue_free(struct kqueue *kq)
{
    filter_unregister_all(kq);
    kqops.kqueue_free(kq);
    free(kq);
}

int
__real_close(int fd);

int
__wrap_close(int fd)
{
    if (fd >= 0) {
        struct kqueue *kq;

        kq = kqueue_lookup(fd);
        if (kq) {
            dbg_printf("Releasing fd=%d kq=%p", fd, kq);

            __kqueue_free(kq);

            return 0;
        }

        dbg_printf("fd=%d is not a kqueue(), continue and call close()", fd);
    }

    return __real_close(fd);
}
