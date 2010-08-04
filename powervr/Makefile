#
# Makefile for Android PowerVR
#

DATE  = $(shell date)
M    ?= $(shell pwd)


ccflags-y = \
	-I$(src) 				\
	-I$(src)/linux 				\
	-I$(src)/device 			\
	-I$(src)/common 			\
	-I$(src)/system 			\
	-I$(src)/bridged 			\
	-I$(src)/omaplfb 			\
	-I$(src)/include 			\
	-include config.h 			\
	-DPVR_BUILD_DIR="\"PowerVR\"" 		\
	-DPVR_BUILD_DATA="\"$(DATE)\""

PVR_COMMON_OBJ := \
	bridged/bridged_pvr_bridge.o		\
	bridged/bridged_sgx_bridge.o		\
	bridged/bridged_support.o		\
	common/buffer_manager.o			\
	common/deviceclass.o			\
	common/devicemem.o			\
	common/handle.o				\
	common/hash.o				\
	common/lists.o				\
	common/mem.o				\
	common/mem_debug.o			\
	common/metrics.o			\
	common/pdump_common.o			\
	common/perproc.o			\
	common/power.o				\
	common/pvrsrv.o				\
	common/queue.o				\
	common/ra.o				\
	common/resman.o				\
	linux/event.o				\
	linux/mm.o				\
	linux/mmap.o				\
	linux/module.o				\
	linux/mutex.o				\
	linux/mutils.o				\
	linux/osfunc.o				\
	linux/osperproc.o			\
	linux/pdump.o				\
	linux/proc.o				\
	linux/pvr_bridge_k.o			\
	linux/pvr_debug.o			\
	system/sysconfig.o			\
	system/sysutils.o			\


SGX_OBJ :=  \
	device/mmu.o				\
	device/pb.o				\
	device/sgxinit.o			\
	device/sgxkick.o			\
	device/sgxpower.o			\
	device/sgxreset.o			\
	device/sgxtransfer.o			\
	device/sgxutils.o			\


OMAPLFB_OBJ := \
	omaplfb/omaplfb_linux.o			\
	omaplfb/omaplfb_displayclass.o		\


omaplfb-objs	:= $(OMAPLFB_OBJ)
pvrsrvkm-objs	:= $(PVR_COMMON_OBJ) $(SGX_OBJ)

obj-m		+= pvrsrvkm.o
obj-m		+= omaplfb.o


all: modules


modules::
	make -C $(KERNEL_SOURCE) M=$(PWD) $@
	$(CROSS_COMPILE)strip --remove-section=.comment --remove-section=.note --strip-unneeded pvrsrvkm.ko
	$(CROSS_COMPILE)strip --remove-section=.comment --remove-section=.note --strip-unneeded omaplfb.ko

clean::
	make -C $(KERNEL_SOURCE) M=$(PWD) $@
	$(RM) modules.order
	find . -name '*~' -type f | xargs $(RM)

