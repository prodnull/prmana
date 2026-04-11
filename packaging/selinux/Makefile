# packaging/selinux/Makefile

all: build

build:
	checkmodule -M -m -o prmana.mod prmana.te
	semodule_package -o prmana.pp -m prmana.mod -f prmana.fc

install: build
	semodule -i prmana.pp

clean:
	rm -f prmana.mod prmana.pp
