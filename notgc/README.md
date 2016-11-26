For performance and space saving, libgc (aka bdwgc or boehmgc) often allocates
memory blocks adjacent. This behavior makes heap buffer overflow and other
issues harder to detect.

`notgc.c` is a thin wrapper which delegates libgc's api to plain malloc/free.
With companion of ASan or other debug allocators, memory bugs will be easier to
find by fuzzers.

Features:
 - By default it passes the request size drectly to underlying allocator. That
   is, `GC_malloc_atomic(1)` will trigger `malloc(1)`.
 - You can set environment variable `SIMULATE_BUCKET=1` to simulate libgc's
   bucket behavior. That is, `GC_malloc_atomic(1)` will trigger `malloc(16)`.
   However, don't relay too much on this simulation because the behavior of
   your libgc may vary because of diffrent platforms, compile options, and libgc
   version. For example, libgc actually allocates 8 bytes for `GC_malloc_atomic(1)`
   on 32 bits system, but the simulation doesn't handle such case.

Known issues:
 - Guarantee memory leak ;) The purpose of notgc.c is for fuzzing test. Not for
   production use.
 - Bad performance. In order to keep code simple, it has O(n) behavior. So far
   this is acceptable.
 - Not fully implemented libgc's api. I only implemented what w3m uses.

How to use:
```
$ make libgc.so.1
$ LD_LIBRARY_PATH=$path_of_this_folder w3m
```
