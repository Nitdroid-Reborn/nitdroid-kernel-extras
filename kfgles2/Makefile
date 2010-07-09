
obj-m := kfgles2.o

kfgles2-objs := kfgles2_main.o kfgles2_hcalls.o


all: modules

modules clean::
	make -C $(LINUX_KERNEL) M=$(PWD) $@

clean::
	$(RM) modules.order *~

