# DTLS performance

## Issue:
OpenSSL performance drop seen in v3.2.0.

## Prepare
```
# Build OpenSSL and install in ~/tmp/.
# Example of using openssl-3.4.0 [commit: 98acb6b].
git clone git@github.com:openssl/openssl.git
REV=98acb6b
git clean -xdf
git co $REV
./Configure --prefix=$HOME/tmp/openssl-$REV --openssldir=$HOME/tmp/openssl-$REV -Wl,-rpath=$HOME/tmp/openssl-$REV/lib64
make clean all install

# Build test tools in this repo.
cd <this repo>/tools/
make certs

# Check the Makefile to make sure correct OpenSSL version is used.
make

# Make sure we can run:
./dtls-server
./dtls-client
```

## Measurements

### Initial measurement from other project

Measure the packets-per-second on baseline and suspected commits.

```
# Baseline.

602ee1f672 | 2022-10-07 | Use common tls_write_records() even for DTLS
~210k pps

# Start of degradation.

248a9bf21a | 2022-10-13 | Start using WPACKET in the dtls write records code
~200k pps (5% degradation)

b9e37f8f57 | 2022-10-13 | Convert dtls_write_records to use standard record layer functions
~180k pps (14% degradation)
```

### Send-loop measurements

* Using separate test binaries, a [client](../tools/dtls-client.c) that sends to a [server](../tools/dtls-server.c).
* 10 minutes runtime.
* Localhost.
* Send 1024 bytes per write.

```
#### OpenSSL 3.1.7
Number of writes: 169200k
282k pps

No registered malloc per write, only during setup:
- Number of writes: 169000k
  malloc-count=9841, realloc-count=336, free-count=4026

#### OpenSSL 3.2.3
Number of writes: 155400k
259k pps
8% decrease from 3.1.7

2 mallocs per write:
- Number of writes: 155600k
  malloc-count=311209981, realloc-count=328, free-count=466804293

#### OpenSSL 3.4.0
Number of writes: 159700k
266k pps
6% decrease from 3.1.7

2 mallocs per write:
- Number of writes: 153300k
  malloc-count=306610965, realloc-count=340, free-count=459904638
```

### Profiling

Flamegraphs:
- [profile_3.1.7.svg](https://raw.githubusercontent.com/bjosv/openssl-experiments/refs/heads/main/issues/images/profile_3.1.7.svg)
- [profile_3.2.3.svg](https://raw.githubusercontent.com/bjosv/openssl-experiments/refs/heads/main/issues/images/profile_3.2.3.svg)
- [profile_diff_3.1.7_to_3.2.3.svg](https://raw.githubusercontent.com/bjosv/openssl-experiments/refs/heads/main/issues/images/profile_diff_3.1.7_to_3.2.3.svg)
- [profile_diff_3.2.3_to_3.4.0.svg](https://raw.githubusercontent.com/bjosv/openssl-experiments/refs/heads/main/issues/images/profile_diff_3.2.3_to_3.4.0.svg)

```
sudo apt-get install bpfcc-tools linux-headers-$(uname -r)

# Start server
./dtls-server

# Start client in other shell (profiling needs sudo)
DURATION=600
sudo ls

# Profile 3.1.7 -------------------------------
./dtls-client &
PID=$!
sudo /usr/sbin/profile-bpfcc -p $PID -F 99 -adf $DURATION > profile_3.1.7.data
kill $PID

# Profile 3.2.3 -------------------------------
./dtls-client &
PID=$!
sudo /usr/sbin/profile-bpfcc -p $PID -F 99 -adf $DURATION > profile_3.2.3.data
kill $PID

# Profile 3.4.0 -------------------------------
./dtls-client &
PID=$!
sudo /usr/sbin/profile-bpfcc -p $PID -F 99 -adf $DURATION > profile_3.4.0.data
kill $PID


# Create flamegraphs using https://github.com/brendangregg/FlameGraph
<repos>/FlameGraph/flamegraph.pl profile_3.1.7.data > profile_3.1.7.svg
<repos>/FlameGraph/flamegraph.pl profile_3.2.3.data > profile_3.2.3.svg

<repos>/FlameGraph/difffolded.pl profile_3.1.7.data profile_3.2.3.data > profile_diff.data
<repos>/FlameGraph/flamegraph.pl profile_diff.data > profile_diff.svg
```

## Links

### DTLS related work package

New write record layer architecture.
https://github.com/openssl/openssl/pull/19424

## TLS v1.2

#### OpenSSL 3.1.7, 10 minutes, TLS v1.2
Number of writes: 237100k (DTLS: 169200k)
395k pps (DTLS: 282k pps)

Number of writes: 237100k
malloc-count=474209785, realloc-count=326, free-count=711303963

2 mallocs per write

#### OpenSSL 3.2.3, 10 minutes, TLS v1.2
Number of writes: 234300k (DTLS: 155400k)
390k pps (DTLS: 259k pps)

Number of writes: 234300k
malloc-count=468609906, realloc-count=318, free-count=702904207

