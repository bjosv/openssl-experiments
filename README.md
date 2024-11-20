# openssl experiments

## Build and install openssl (with RPATH since we use prefix)
```
git clone git@github.com:openssl/openssl.git

REV=602ee1f672
REV=248a9bf21a
REV=b9e37f8f57

# Latest DTLS change
REV=f08be09651
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

./Configure --prefix=$HOME/tmp/openssl-$REV --openssldir=$HOME/tmp/openssl-$REV -Wl,-rpath=$HOME/tmp/openssl-$REV/lib64
make clean all install
```
