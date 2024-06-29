# CGO AIDE build instructions

# Installing AIDE build dependencies

```
sudo dnf install e2fsprogs-devel audit-libs-devel libattr-devel flex bison \ zlib-devel libgcrypt-devel audit-libs-devel \
libacl-devel libselinux-devel libtool -y
```

# Building AIDE

```
sh ./autogen.sh

./configure --with-zlib --disable-static --with-posix-acl --with-selinux --with-xattr --with-e2fsattrs --with-audit

make

ln -s ./include/aide_cgo.h /<go-project>/aide_cgo.h
ln -s ./.libs/libaide.so /<go-project>/libaide.so
ln -s ./.libs/libaide.so.0 /<go-project>/libaide.so.0
ln -s ./.libs/libaide.so.0.0.0 /<go-project>/libaide.so.0.0.0
ln -s ./.libs/libaide.la /<go-project>/libaide.la
```
