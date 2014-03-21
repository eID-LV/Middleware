Summary: Middleware for using Latvia-eid smart cards
Name: latvia-eid-middleware
Version: 1.1.0
Release: 1
License: LGPLv2+
Group: Applications/System
Requires: openssl, pcsc-lite, pcsc-lite-libs, zlib

%description
This package also contains the PinTool (otlv-pintool) that is used to read the content of the card and change its PIN value.

%prep

%build

%install

%clean

%post
ln -sf /opt/latvia-eid/lib/otlv-pkcs11.so /usr/lib
ln -sf /opt/latvia-eid/bin/otlv-pintool /usr/bin

mkdir -p /usr/lib/pkcs11
ln -sf ../otlv-pkcs11.so /usr/lib/pkcs11/.
ln -sf /opt/latvia-eid/share/doc/Latvia-eID-Middleware/otlv-pintool.xpm /usr/share/pixmaps/.
ln -sf /opt/latvia-eid/share/doc/Latvia-eID-Middleware/otlv-pintool.desktop /usr/share/applications/.
/sbin/ldconfig /opt/latvia-eid/lib
/sbin/ldconfig /usr/lib/pkcs11
/sbin/ldconfig

%postun
rm -f /usr/lib/otlv-pkcs11.so
rm -f /usr/lib/pkcs11/otlv-pkcs11.so
rm -f /usr/bin/otlv-pintool
rm -fr /opt/latvia-eid
rm -f /usr/share/pixmaps/otlv-pintool.xpm
rm -f /usr/share/applications/otlv-pintool.desktop
/sbin/ldconfig
  
%files
%defattr(-,root,root)
%doc


