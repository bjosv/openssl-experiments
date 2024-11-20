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

### Initial measurement in other project

Measure the packets-per-second with suspected commits.

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

### Send loop measurements, 10 minutes runtime.

Using separate test binaries, a [client](../tools/dtls-client.c) that sends to a [server](../tools/dtls-server.c).

```
# OpenSSL 3.1.7
Number of writes: 169200k
282k pps

# OpenSSL 3.2.3
Number of writes: 155400k
259k pps
8% decrease from 3.1.7

# OpenSSL 3.4.0
Number of writes: 159700k
266k pps
6% decrease from 3.1.7
```

### Profiling

Flamegraphs:
- [profile_3.1.7.svg](images/profile_3.1.7.svg)
- [profile_3.2.3.svg](images/profile_3.2.3.svg)
- [profile_diff_3.1.7_to_3.2.3.svg](images/profile_diff_3.1.7_to_3.2.3.svg)
- [profile_diff_3.2.3_to_3.4.0.svg](images/profile_diff_3.2.3_to_3.4.0.svg)

```
sudo apt-get install bpfcc-tools linux-headers-$(uname -r)

DURATION=600
sudo ls
./dtls-server

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
