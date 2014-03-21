#!/bin/sh
cd ../opensc-0.12.2
chmod gou+x configure
chmod gou+x config.sub
chmod gou+x config.status
chmod gou+x depcomp

./configure --prefix=/opt/latvia-eid \
--sysconfdir=/opt/latvia-eid/etc \
--disable-dependency-tracking \
--enable-shared \
--disable-static \
--enable-strict \
--disable-assert

make clean && make
sudo make install
sudo rm -fr /opt/latvia-eid/lib/*.a
sudo rm -fr /opt/latvia-eid/share/Latvia-eID-Middleware/*.profile
cd ../PinTool
make clean && make
sudo make install
cd ../build
rm -fr debian/opt
rm -fr *.deb
mkdir -p debian/deb_tmp/opt
cp -p -R /opt/latvia-eid debian/deb_tmp/opt
cp -p -R debian/DEBIAN debian/deb_tmp
find ./debian/deb_tmp -type d | xargs chmod 755
strip debian/deb_tmp/opt/latvia-eid/bin/*
strip debian/deb_tmp/opt/latvia-eid/lib/*
upx debian/deb_tmp/opt/latvia-eid/bin/otlv-pintool
rm -fr `find debian/deb_tmp | grep .svn`
fakeroot dpkg-deb --build debian/deb_tmp
mv debian/deb_tmp.deb latvia-eid-middleware_1.1.0-1_i386.deb
rm -fr debian/deb_tmp*

