======
PPIPAA
======

Prefix-Preserving IP Address Anonymization

THERE ARE SERIOUS PROBLEMS WITH THIS IMPLEMENTATION. DO NOT USE!

Table of Contents
-----------------

* `Introduction`_

   * `Anonymization Algorithm`_

   * `De-anonymization Mitigations`_

* `Build and Test`_

* `Example Usage`_

* `Future`_

* `Dependencies`_

* `References`_

Introduction
------------

IP addresses are sometime considered sensitive information and need to be
anonymized before being shared. The `CryptoPAn <References_>`_ algorithm is an
established way to perform the anonymization. It preserves the prefix property
which means that two addresses which share a N-bit prefix before anonymization
will share a N-bit prefix after anonymization. This is useful for inferring
that two addresses are on the same subnet, for example.

The original implementation of the algorithm is called CryptoPAn and was
written in C++. Another implementation, called CryptopANT, is written in C.
There are also other implementations for other languages which can be found by
searching the Internet.


Anonymization Algorithm
~~~~~~~~~~~~~~~~~~~~~~~

The core of the algorithm is the relationship defining the `ith` bit :math:`b_i`
in terms of the bits in the prefix of the original IP address,
:math:`a_1..a_i`:

.. math::

   b_i = f_i(a_1 a_2 ... a_i) = L(R(P(a_1 a_2 ... a_i), k)

for :math:`i = 1..n`, where :math:`n=32` for IPv4 addresses or :math:`n=128`
for IPv6 addresses. The bits are numbered from most significant to the least
(otherwise it would not be prefix-preserving), The function, :math:`L`,
returns the least-significant bit, :math:`R` is a pseudo random function
(PRF), and :math:`P` is the pad function that pads to the size required by
:math:`R`. The parameter, :math:`k`, is the key used by the PRF.

The functions for the three most significant bits show the general pattern:

.. math::

   b_1 = f_1(a_1) = L(R(P(a_1), k)

   b_2 = f_2(a_1 a_2) = L(R(P(a_1 a_2), k)

   b_3  = f_2(a_1 a_2 a_3) = L(R(P(a_1 a_2 a_3), k)

This formulation describes a family of anonymization algorithms with the
prefix-preservation property. Many different PRFs can be chosen. CryptoPAn and
CryptopANT use the electronic cookbook (ECB) mode of AES symmetric encryption
with :math:`k` as the encryption key. PPIPAA uses the generic hash function
from the Sodium cryptographic library, which is the fast and secure Blake2b
hash. A key is not required for hashing but using different keys produce
different hashes. As such, :math:`k` can be thought of as an anonymization
space identifier.

Concerning the pad, CryptoPAn uses the first 128-bits from a 256-bit secret
(which should be randomly generated) as the key and the second 128-bits as the
pad. CryptopANT does this as well. PPIPAA also uses a randomly generated
128-bit key and a 128-bit pad.


De-anonymization Mitigations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The original implementation anonymized all the bits in (IPv4) addresses.
Depending on the attack model, anonymizing all the bits potentially allows
attackers to mount a known-prefix attack. It is often quite easy to identify
well-known hosts, such as web, mail, or DNS serves. Due to
prefix-preservation, other addresses which share the same prefixes as the
identified IP addresses contribute additional information that can be used in
the known-plaintext attack.

Because of this, it is likely better to partially anonymized addresses leaving
the network prefixes of the institution (which are public knowledge anyway) in
the clear. PPIPAA leaves that decision to you in the form of a `prefix`
parameter which specifies the number of most significant bits that are passed
through without anonymization. But based on the above reasoning, it is
probably best to only anonymize the host identifier portion of IP addresses.

One approach is to copy the most significant bits through unchanged then begin
anonymizing the least significant bits using the CryptoPAn algorithm. To avoid
potential side-channel attacks, PPIPAA always anonymizes all the bits then
replaces the anonymized network prefix with the original network prefix.
Assuming the PRF takes the same amount of time, PPIPAA should always take the
same amount of time to anonymize all IPv4 addresses regardless of the number
of prefix bits passing through unchanged. Likewise for IPv6 addresses.


Reversing
~~~~~~~~~

It is often useful to reverse an anonymized address back to the original,
perhaps so a network anomaly can be investigated. Rather than making the
process reversible for legitimate uses and thereby risk making it easy for
attackers, PPIPAA explicitly uses a cryptographic hash as the PRF to hinder
reversibility.

If reversibility is required, the mapping from original to anonymized IP
addresses must be maintained. One approach is to save a copy of the mappings
to a file. Furthermore, the mappings can be used as a cache which amortizes
the cost of anonymization for frequently observed IP addresses. This is the
recommended approach. As there are different ways to implement a cache with
different runtime behavior, caching is not included in the library.


Build and Test
--------------

The default target in the make file builds the library and runs the tests. It
also builds and executes the `example program <#usage>`_ below. The default
compiler is gcc but clang works as well.

.. code:: shell

   $ make
   gcc -I ~/src/uint128 -MM -MF ppipaa_tests.d ppipaa_tests.c
   pandoc -o LICENSE.html LICENSE.rst
   pandoc -o README.html README.rst
   gcc -fPIC -I . -I ~/src/uint128 -Wall -Wpedantic -Wextra   -c -o ppipaa.o ppipaa.c
   gcc -fPIC -I . -I ~/src/uint128 -Wall -Wpedantic -Wextra   -c -o example.o example.c
   ar rcs libppipaa.a ppipaa.o example.o
   gcc -shared -o libppipaa.so ppipaa.o example.o
   gcc -fPIC -I . -I ~/src/uint128 -Wall -Wpedantic -Wextra -c ppipaa_tests.c
   gcc -shared -o ppipaa_tests.so ppipaa_tests.o ppipaa.o example.o -lsodium -lcgreen
   gcc -o example example.o -lsodium libppipaa.a
   Running "ppipaa_tests" (24 tests)...
   "ppipaa": 520 passes in 317ms.
   Completed "ppipaa_tests": 520 passes in 317ms.
   ./example
   Key1: original=198.51.100.47   0xC633642F -> anonymized=198.51.0.199    0xC63300C7
   Key2: original=198.51.100.47   0xC633642F -> anonymized=198.51.119.167  0xC63377A7
   Key1: original=198.51.100.47   0xC633642F -> anonymized=198.51.0.199    0xC63300C7


Example Usage
-------------

The following is a functional, if contrived, example of how to anonymize IP
addresses using the library. It demonstrates the use of all the functionality,
albeit with IPv4 only.

.. include:: example.c
   :code: C


Future
------

The library is complete with respect to the anonymization of IP addresses. A
possible addition might be to incorporate a cache, as discussed in
`Reversing`_ but it isn't clear that this is a universal need and adding it
could affect side-channel resistance. For these reasons, it isn't currently
implemented.

Please submit an issue if something is missing or you find a bug.


Dependencies
------------

* C compiler: `gcc <https://gcc.gnu.org/>`_ 8.3.0 and `clang <https://clang.llvm.org/>`_ 7.1.0 have been tested

* `libsodium <https://doc.libsodium.org/>`_ cryptographic library: tested with 1.0.18

* `Cgreen <https://cgreen-devs.github.io/>`_ testing framework: tested with 1.3.0

* `pandoc <https://pandoc.org/>`_ documentation processor: 2.7.3 has been tested


Alternate Implementations
-------------------------

- `CryptoPAn <https://web.archive.org/web/20181220030621/https://www.cc.gatech.edu/computing/Telecomm/projects/cryptopan/>`_
  is the original implementation of the CryptoPAn algorithm in C++ anonymized
  IPv4 addresses only. Unfortunately, the web page is no longer available.
  However, a copy can be found at the Internet Archive.

- `CryptopANT <https://ant.isi.edu/software/cryptopANT/index.html>`_ is an
  independent implementation in C based on the CryptoPAn publications from
  ISI. It anonymized both IPv4 and IPv6 addresses and has support for partial
  anonymization. Even though the CryptoPAn algorithm was designed to be
  executed in parallel, the CryptopANT implementation depends upon OpenSSL
  which is not thread safe and requires critical section protection. This has
  a significant impact on performance. The lack of thread safety and the
  resulting performance impact was a motivation in developing PPIPAA.


References
----------

- Jinliang Fan, Jun Xu, Mostafa H. Ammar, Sue B. Moon, "Prefix-preserving IP
  address anonymization: measurement-based security evaluation and a new
  cryptography-based scheme", Computer Networks, Volume 46, Issue 2, 7 October
  2004, Pages 253-272.
  https://www.sciencedirect.com/science/article/pii/S1389128604001197
