PREFIX= /usr
SYSCONFDIR= /etc
MANDIR= $(PREFIX)/share/man
V=`cat version.txt|cut -d ' ' -f 2`
CFLAGS = -DPREFIX=\"$(PREFIX)\" -DSYSCONFDIR=\"$(SYSCONFDIR)\"  -DMANDIR=\"$(MANDIR)\" -Os -Wall -march=i586 -g -DVERSION=\"$(V)\"
CC=musl-gcc-x86_32
ifinfo:	ifinfo.o stats64.o jelist.o jelopt.o
	$(CC) -o ifinfo ifinfo.o stats64.o jelist.o jelopt.o
clean:
	rm -f *.o ifinfo
tarball:	clean
	make-tarball.sh
rpm:	ifinfo
	bar -c --license=GPLv2+ --name ifinfo ifinfo-$(V)-1.rpm --prefix=/usr/bin --fuser=root --fgroup=root --version=$(V) --release=1 ifinfo
