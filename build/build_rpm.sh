#!/bin/sh
cd redhat
rm -fr BUILDROOT
rm -fr BUILD
rm -fr RPMS
rm -fr SOURCES
rm -fr SPECS
rm -fr SRPMS

mkdir -p BUILDROOT/latvia-eid-middleware-1.1.0-1.i386/opt
mkdir -p BUILD
mkdir -p RPMS
mkdir -p SOURCES
mkdir -p SPECS
mkdir -p SRPMS

echo "%_topdir `pwd`" > ~/.rpmmacros
echo "%_builddir %{_topdir}/BUILD" >> ~/.rpmmacros
echo "%_rpmdir %{_topdir}/RPMS" >> ~/.rpmmacros
echo "%_sourcedir %{_topdir}/SOURCES" >> ~/.rpmmacros
echo "%_specdir %{_topdir}/SPECS" >> ~/.rpmmacros
echo "%_srcrpmdir %{_topdir}/SRPMS" >> ~/.rpmmacros

cd ../../opensc-0.12.2
chmod ugo+x bootstrap
./bootstrap
chmod ugo+x configure
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
cd ../PinTool
make clean && make -f Makefile.rhel
sudo make -f Makefile.rhel install

cd ../build
sudo rm -fr /opt/latvia-eid/lib/*.a
sudo rm -fr /opt/latvia-eid/share/Latvia-eID-Middleware/*.profile
sudo strip /opt/latvia-eid/bin/*
sudo strip --strip-unneeded /opt/latvia-eid/lib/*.so*
sudo upx /opt/latvia-eid/bin/otlv-pintool

rm -fr `find /opt/latvia-eid | grep .svn`
cp -p -R /opt/latvia-eid redhat/BUILDROOT/latvia-eid-middleware-1.1.0-1.i386/opt/.

cp redhat/latvia-eid.spec redhat/latvia-eid-build.spec

echo "`find /opt/latvia-eid -type l`" >> redhat/latvia-eid-build.spec
echo "`find /opt/latvia-eid -type f`" >> redhat/latvia-eid-build.spec
echo "%changelog" >> redhat/latvia-eid-build.spec

rm -fr *.rpm
rpmbuild -bb redhat/latvia-eid-build.spec
sudo rm -fr /opt/latvia-eid
mv redhat/RPMS/i386/*.rpm .
rm -fr redhat/BUILDROOT
rm -fr redhat/BUILD
rm -fr redhat/RPMS
rm -fr redhat/SOURCES
rm -fr redhat/SPECS
rm -fr redhat/SRPMS
rm -fr ~/.rpmmacros


