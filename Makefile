#?V=`cat version.txt|cut -d ' ' -f 2`
#%ifswitch --diet diet DIET
#%setifdef DIET -D_BSD_SOURCE DIETINC
#%setifdef DIET -L/opt/diet/lib DIETLIB
#%prepifdef DIET /opt/diet/lib:/opt/diet/include
#%switch --prefix PREFIX
#%switch --mandir MANDIR
#%switch --sysconfdir SYSCONFDIR
#%ifnswitch --prefix /usr PREFIX
#%ifnswitch --sysconfdir /etc SYSCONFDIR
#%ifnswitch --mandir $(PREFIX)/share/man MANDIR
#?CFLAGS = $(DIETINC) -DPREFIX=\"$(PREFIX)\" -DSYSCONFDIR=\"$(SYSCONFDIR)\"  -DMANDIR=\"$(MANDIR)\" -Os -Wall -march=i586 -g -DVERSION=\"$(V)\"
#?CC=$(DIET) gcc
#?ifinfo:	ifinfo.o stats64.o jelist.o jelopt.o
#?	$(CC) $(DIETLIB) -o ifinfo ifinfo.o stats64.o jelist.o jelopt.o
#?clean:
#?	rm -f *.o ifinfo
#?tarball:	clean
#?	make-tarball.sh
DIET= diet
DIETINC=-D_BSD_SOURCE
DIETLIB=-L/opt/diet/lib
PREFIX= /usr
SYSCONFDIR= /etc
MANDIR= $(PREFIX)/share/man
V=`cat version.txt|cut -d ' ' -f 2`
CFLAGS = $(DIETINC) -DPREFIX=\"$(PREFIX)\" -DSYSCONFDIR=\"$(SYSCONFDIR)\"  -DMANDIR=\"$(MANDIR)\" -Os -Wall -march=i586 -g -DVERSION=\"$(V)\"
CC=$(DIET) gcc
ifinfo:	ifinfo.o stats64.o jelist.o jelopt.o
	$(CC) $(DIETLIB) -o ifinfo ifinfo.o stats64.o jelist.o jelopt.o
clean:
	rm -f *.o ifinfo
tarball:	clean
	make-tarball.sh
