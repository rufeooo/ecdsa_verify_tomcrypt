#!/bin/bash
clang main.c -O0 -g -DLTM_DESC -L~/external/libtomcrypt/ -l:libtomcrypt.a -ltommath
