## The ppipaa IP address anonymization library
##
## Copyright (C) 2020, Mark Gardner <mkg@vt.edu>.
##
## This file is part of ppipaa.
##
## ppipaa is free software: you can redistribute it and/or modify it under the
## terms of the GNU Lesser General Public License as published by the Free
## Software Foundation, either version 3 of the License, or (at your option)
## any later version.
##
## ppipaa is distributed in the hope that it will be useful, but WITHOUT ANY
## WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
## FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
## more details.
##
## You should have received a copy of the GNU Lesser General Public License
## along with ppipaa. If not, see <https://www.gnu.org/licenses/>.

CC     ?= gcc
CFLAGS  = -fPIC -I . -I $(U128LIB) -Wall -Wpedantic -Wextra
LDFLAGS = -lsodium
DFLAGS  = -I $(U128LIB) -MM -MF

SRC     = ppipaa.c example.c
OBJ     = ${SRC:.c=.o}
DEP     = ${SRC:.c=.d}

STATLIB = libppipaa.a
DYNLIB  = libppipaa.so

U128LIB = ~/src/uint128

TESTSRC = $(wildcard *_tests.c)
TESTOBJ = ${TESTSRC:.c=.o}
TESTDEP = ${TESTSRC:.c=.d}
TESTLIB = ${TESTSRC:.c=.so}

DOCSRC  = $(wildcard *.rst)
DOCHTML = ${DOCSRC:.rst=.html}

.PHONY: all lib html tests

all: html lib tests example

example: example.o
	$(CC) -o $@ $^ $(LDFLAGS) libppipaa.a

lib: $(STATLIB) $(DYNLIB)

$(STATLIB): $(OBJ)
	ar rcs $@ $^

$(DYNLIB): $(OBJ)
	$(CC) -shared -o $@ $^

tests: $(TESTLIB) example
	@for test in $(TESTLIB) ; do cgreen-runner $${test} ; done
	./example

%_tests.so: %_tests.o $(OBJ)
	$(CC) -shared -o $@ $^ $(LDFLAGS) -lcgreen

%.o: %.c | %.d
	$(CC) $(CFLAGS) -c $^

%.d: %.c
	$(CC) $(DFLAGS) $(patsubst %.c,%.d,$^) $^

html: $(DOCHTML)

%.html: %.rst
	pandoc -o $@ $^

.PHONY: clean distclean

clean:
	rm -f $(OBJ) $(DEP) $(TESTDEP) $(TESTOBJ) $(TESTLIB) *.gch *.d *.a *.so $(DOCHTML)

distclean: clean
	rm -f *~ example

-include $(TESTDEP)
