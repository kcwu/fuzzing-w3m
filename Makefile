CC = clang-3.8
CFLAGS += -O0 -g

CONFIGURE_ARGS=--enable-image=no

all:

report:
	python reproduce.py

init:
	make fetch-depend
	make build-depend

fetch-depend:
	# for libdislocator
	git clone https://github.com/mcarpenter/afl.git
	# tats
	git clone https://github.com/tats/w3m.git targets/w3m-tats
	git clone https://github.com/tats/w3m.git -b 'v0.5.3+git20160718' targets/w3m-tats.20160718
	# origin
	cd targets && wget 'http://downloads.sourceforge.net/project/w3m/w3m/w3m-0.5.3/w3m-0.5.3.tar.gz' && tar zxf w3m-0.5.3.tar.gz
	cd targets/w3m-0.5.3 && patch -p1 < ../../files/0001-s-file_handle-w3m_file_handle.patch
	cd targets/w3m-0.5.3 && patch -p1 < ../../files/0002-fix-build.patch

build-depend:
	cd afl/libdislocator && make
	cd notgc && make

do-build:
	[ -n "$(T)" ] && [ -d "targets/$(T)" ]
	cd targets/$(T) && CC="$(CC)" ./configure $(CONFIGURE_ARGS) && make clean && make all -j8
	cp targets/$(T)/w3m $(OUT_FILE)

do-build-variants:
	CFLAGS='' make do-build OUT_FILE=$(T)
	CFLAGS='-fsanitize=address' make do-build OUT_FILE=$(T).asan
	CFLAGS='-fsanitize=memory' make do-build OUT_FILE=$(T).msan
	CFLAGS='-fsanitize=undefined' make do-build OUT_FILE=$(T).ubsan

build:
	make do-build-variants T=w3m-tats
	make do-build-variants T=w3m-tats.20160718
	make do-build-variants T=w3m-0.5.3
