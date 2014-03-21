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
rm -fr debian64/opt
rm -fr *.deb
mkdir -p debian64/deb_tmp/opt
cp -p -R /opt/latvia-eid debian64/deb_tmp/opt
cp -p -R debian64/DEBIAN debian64/deb_tmp
find ./debian64/deb_tmp -type d | xargs chmod 755
strip debian64/deb_tmp/opt/latvia-eid/bin/*
strip debian64/deb_tmp/opt/latvia-eid/lib/*
upx debian64/deb_tmp/opt/latvia-eid/bin/otlv-pintool
rm -fr `find debian64/deb_tmp | grep .svn`
fakeroot dpkg-deb --build debian64/deb_tmp
mv debian64/deb_tmp.deb latvia-eid-middleware_1.1.0-1_amd64.deb
rm -fr debian64/deb_tmp*

