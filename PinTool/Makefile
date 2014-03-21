PREFIX = /opt/latvia-eid
FULLNAME = otlv-pintool

WX_CFLAGS = -I../wxWidgets/lib/wx/include/gtk2-unicode-static-2.9 -I../wxWidgets/include/wx-2.9 -D_FILE_OFFSET_BITS=64 -DwxDEBUG_LEVEL=0 -D__WXGTK__ -pthread
WX_LIBS = -L../wxWidgets/lib -pthread ../wxWidgets/lib/libwx_gtk2u-2.9.a -pthread -lgtk-x11-2.0 -lgdk-x11-2.0 -latk-1.0 -lgio-2.0 -lpangoft2-1.0 -lgdk_pixbuf-2.0 -lm -lpangocairo-1.0 -lcairo -lpango-1.0 -lfreetype -lfontconfig -lgobject-2.0 -lgmodule-2.0 -lgthread-2.0 -lrt -lglib-2.0 -lX11 -lXxf86vm -lSM -lwxregexu-2.9 -lwxexpat-2.9 -lwxtiff-2.9 -lwxjpeg-2.9 -lwxpng-2.9 -lwxzlib-2.9 -ldl -lm

CXXFLAGS = -O2  -I. -DNDEBUG -D_REENTRANT -DLATVIAEID_PREFIX="\"$(PREFIX)\"" $(WX_CFLAGS)

LDFLAGS = -lcrypto $(WX_LIBS)

SRCS = cryptoki.cpp main.cpp PinTool.cpp
OBJECTS = $(SRCS:.cpp=.o)

#######################
# don't modify
#######################
bindir = $(PREFIX)/bin

all: $(FULLNAME)

$(FULLNAME): $(OBJECTS)
	$(CXX) -o $(FULLNAME) $(OBJECTS) $(LDFLAGS)
	
-include $(OBJECTS:.o=.d)

.cpp.o:
	$(CXX) $(CXXFLAGS) -c $< -o $@
	$(CXX) -MM $(CXXFLAGS) $*.cpp > $*.d
	@mv -f $*.d $*.d.tmp
	@sed -e 's|.*:|$*.o:|' < $*.d.tmp > $*.d
	@sed -e 's/.*://' -e 's/\\$$//' < $*.d.tmp | fmt -1 | \
	  sed -e 's/^ *//' -e 's/$$/:/' >> $*.d
	@rm -f $*.d.tmp

install: all
	mkdir -p $(bindir)
	cp $(FULLNAME) $(bindir)/.
	mkdir -p $(bindir)/help/en/contents
	cp help/en/help.htm $(bindir)/help/en
	cp help/en/contents/* $(bindir)/help/en/contents	
	mkdir -p $(bindir)/help/lv/contents
	cp help/lv/help.htm $(bindir)/help/lv
	cp help/lv/contents/* $(bindir)/help/lv/contents		
	mkdir -p $(bindir)/Languages/lv
	cp *.mo $(bindir)/Languages/lv/.
	mkdir -p $(PREFIX)/share/doc/Latvia-eID-Middleware
	cp ../CHANGES $(PREFIX)/share/doc/Latvia-eID-Middleware/changelog
	cp ../CHANGES $(PREFIX)/share/doc/Latvia-eID-Middleware/changelog.Debian
	cp ../CHANGES.txt $(bindir)
	cp otlv-pintool.desktop $(PREFIX)/share/doc/Latvia-eID-Middleware/
	cp res/pintoolicon.xpm $(PREFIX)/share/doc/Latvia-eID-Middleware/otlv-pintool.xpm
	
uninstall:
	rm -fr $(bindir)/$(FULLNAME)
	rm -fr $(bindir)/help
	rm -fr $(bindir)/Languages
	rm -fr $(PREFIX)/share/doc/Latvia-eID-Middleware/changelog
	rm -fr $(PREFIX)/share/doc/Latvia-eID-Middleware/changelog.Debian
	rm -fr $(PREFIX)/share/doc/Latvia-eID-Middleware/otlv-pintool.desktop
	rm -fr $(PREFIX)/share/doc/Latvia-eID-Middleware/otlv-pintool.xpm
	
.PHONY: clean uninstall install
clean:
	rm -fr *.o *.d
	rm -fr $(FULLNAME)


