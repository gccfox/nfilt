KDIR = linux
obj-m := nfilt.o

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules 

clean:
	$(MAKE) -C linux M=$(PWD) clean
