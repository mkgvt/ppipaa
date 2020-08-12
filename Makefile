CC      = gcc
CFLAGS  = -fPIC -I. -Wall

LD      = gcc
LDFLAGS = -shared -lcgreen -lsodium

RM     = rm -f

TESTS=$(patsubst %.c,%.so,$(wildcard *_tests.c))

.PHONY: all tests
all: $(TESTS) tests

tests: $(TESTS)
	@for test in $(TESTS) ; do \
	  echo ; \
	  echo cgreen-runner $${test} ; \
	  cgreen-runner $${test} ; \
        done

%_tests.so: %_tests.o ipanon.o
	$(CC) -shared -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

.PHONY: clean distclean
clean:
	$(RM) *_tests.so *.o

distclean: clean
	$(RM) *~
