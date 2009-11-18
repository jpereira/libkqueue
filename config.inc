program="libkqueue"
version="0.3"
cflags="-fPIC -I./include -I./src/common -Wall -Werror"
sources="src/common/*.c"
libdepends=""
mans="kqueue.2"
headers="src/common/private.h"
extra_dist="*.in"
subdirs="src include test"

# Package metadata
pkg_summary="Emulates the kqueue and kevent system calls"
pkg_description="Emulates the kqueue and kevent system calls"
license="BSD"
author="Mark Heily"

pre_configure_hook() {
  if [ "$debug" = "yes" ] ; then
      cflags="$cflags -DKQUEUE_DEBUG"
  fi

  libdepends=" -L$libdir"
  if [ $target = "linux" ] ; then
      libdepends="$libdepends -lpthread -lrt"
      required_headers="sys/epoll.h sys/inotify.h 
                        sys/signalfd.h sys/timerfd.h sys/eventfd.h"
  fi
}

post_configure_hook() {
    finalize target "$target"
    sources="$sources src/$target/*.c"
}