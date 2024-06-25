
ifneq ($(KERNELRELEASE),)
obj-m   := hello_world.o
else

ifndef $(KERNEL_DIR)
KERNEL_DIR    := /lib/modules/$(shell uname -r)/build
endif

PWD     := $(shell pwd)

.PHONY: all clean install modules_install
all:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules
  

install: modules_install
modules_install:
	make -C ${KERNEL_DIR} M=$(PWD) $@;
	depmod -a;

clean:
	make -C ${KERNEL_DIR} M=$(PWD) $@;
	rm -rf modules.order

endif