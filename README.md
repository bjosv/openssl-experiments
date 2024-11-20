# openssl experiments

## Build and install OpenSSL

 ```
git clone git@github.com:openssl/openssl.git

# openssl-3.1.7
REV=3c6a7a1
# openssl-3.2.3
REV=45fda76
# openssl-3.3.2
REV=fb7fab9
# openssl-3.4.0
REV=98acb6b

git clean -xdf
git co $REV

# Use RPATH since we use prefix.
./Configure --prefix=$HOME/tmp/openssl-$REV --openssldir=$HOME/tmp/openssl-$REV -Wl,-rpath=$HOME/tmp/openssl-$REV/lib64
make clean all install
```
