/*
   This header is the glue you need to make afl-fuzz and your statically
   instrumented target play nice together.

   The entry-point __afl_persistent_loop is meant to be called at the start of the harness,
   in a loop like below. The function will set up everything needed to communicate
   and synchronize with afl-fuzz - if it is present (named pipe, shm, etc).

      while(__afl_persistent_loop()) {
          // init state
          // exercise target
          // clear state
      }

   If afl-fuzz isn't detected, then the function will simply return TRUE the first
   time so that the body gets executed once.
*/

#pragma once
#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

    BOOL __afl_persistent_loop();

#ifdef __cplusplus
}
#endif