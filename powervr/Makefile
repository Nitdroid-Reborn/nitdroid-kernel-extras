#
# Makefile for Android PowerVR
#

CONFIG_PVR=m
CONFIG_OMAPLFB=m


DATE  = $(shell date)
M    ?= $(shell pwd)


ccflags-y = \
	-I$(src) \
	-I$(src)/sgx \
	-I$(src)/omap3430 \
	-include $(src)/pvr_config.h \
	-DPVR_BUILD_DIR="\"PowerVR\""


PVR_COMMON_OBJ := \
	osfunc.o \
	mutils.o \
	mmap.o \
	module.o \
	pdump.o \
	proc.o \
	pvr_bridge_k.o \
	pvr_debug.o \
	mm.o \
	mutex.o \
	event.o \
	osperproc.o \
	buffer_manager.o \
	devicemem.o \
	deviceclass.o \
	handle.o \
	hash.o \
	metrics.o \
	pvrsrv.o \
	queue.o \
	ra.o \
	resman.o \
	power.o \
	mem.o \
	pdump_common.o \
	bridged_support.o \
	bridged_pvr_bridge.o \
	perproc.o \
	lists.o \
	omap3430/sysconfig.o \
	omap3430/sysutils.o

SGX_OBJ :=  \
	sgx/bridged_sgx_bridge.o \
	sgx/sgxinit.o \
	sgx/sgxpower.o \
	sgx/sgxreset.o \
	sgx/sgxutils.o \
	sgx/sgxkick.o \
	sgx/sgxtransfer.o \
	sgx/mmu.o \
	sgx/pb.o

OMAPLFB_OBJ := \
	omaplfb/omaplfb_displayclass.o \
	omaplfb/omaplfb_linux.o


omaplfb-objs := $(OMAPLFB_OBJ)
powervr-objs := $(PVR_COMMON_OBJ) $(SGX_OBJ)

obj-$(CONFIG_PVR) += powervr.o
obj-$(CONFIG_OMAPLFB) += omaplfb.o


all: modules

modules clean::
	make -C $(LINUX_KERNEL) M=$(PWD) $@

strip:: modules
	arm-none-linux-gnueabi-strip --remove-section=.comment --remove-section=.note --strip-unneeded powervr.ko
	arm-none-linux-gnueabi-strip --remove-section=.comment --remove-section=.note --strip-unneeded omaplfb.ko

clean::
	$(RM) modules.order *~

