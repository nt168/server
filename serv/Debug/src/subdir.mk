################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/arg_parser.c \
../src/arg_validity_check.c \
../src/base64.c \
../src/cfg.c \
../src/channel.c \
../src/cjson.c \
../src/common.c \
../src/daemon.c \
../src/ddr.c \
../src/env_check.c \
../src/fatal.c \
../src/filebrowser.c \
../src/handle.c \
../src/hashmap.c \
../src/history.c \
../src/loader.c \
../src/log.c \
../src/misc.c \
../src/mutexs.c \
../src/ntmp.c \
../src/nttabs.c \
../src/pcie.c \
../src/phy_mix.c \
../src/phy_ssh.c \
../src/phy_tty.c \
../src/poller.c \
../src/procmgr.c \
../src/results.c \
../src/rmt_exec.c \
../src/scanner.c \
../src/server.c \
../src/setproctitle.c \
../src/shmlst.c \
../src/ssh_tst.c \
../src/str.c \
../src/tpool.c 

C_DEPS += \
./src/arg_parser.d \
./src/arg_validity_check.d \
./src/base64.d \
./src/cfg.d \
./src/channel.d \
./src/cjson.d \
./src/common.d \
./src/daemon.d \
./src/ddr.d \
./src/env_check.d \
./src/fatal.d \
./src/filebrowser.d \
./src/handle.d \
./src/hashmap.d \
./src/history.d \
./src/loader.d \
./src/log.d \
./src/misc.d \
./src/mutexs.d \
./src/ntmp.d \
./src/nttabs.d \
./src/pcie.d \
./src/phy_mix.d \
./src/phy_ssh.d \
./src/phy_tty.d \
./src/poller.d \
./src/procmgr.d \
./src/results.d \
./src/rmt_exec.d \
./src/scanner.d \
./src/server.d \
./src/setproctitle.d \
./src/shmlst.d \
./src/ssh_tst.d \
./src/str.d \
./src/tpool.d 

OBJS += \
./src/arg_parser.o \
./src/arg_validity_check.o \
./src/base64.o \
./src/cfg.o \
./src/channel.o \
./src/cjson.o \
./src/common.o \
./src/daemon.o \
./src/ddr.o \
./src/env_check.o \
./src/fatal.o \
./src/filebrowser.o \
./src/handle.o \
./src/hashmap.o \
./src/history.o \
./src/loader.o \
./src/log.o \
./src/misc.o \
./src/mutexs.o \
./src/ntmp.o \
./src/nttabs.o \
./src/pcie.o \
./src/phy_mix.o \
./src/phy_ssh.o \
./src/phy_tty.o \
./src/poller.o \
./src/procmgr.o \
./src/results.o \
./src/rmt_exec.o \
./src/scanner.o \
./src/server.o \
./src/setproctitle.o \
./src/shmlst.o \
./src/ssh_tst.o \
./src/str.o \
./src/tpool.o 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.c src/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -DSQLITE_THREADSAFE=2 -I"../libdepds/libssh_0.9.3/include" -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


clean: clean-src

clean-src:
	-$(RM) ./src/arg_parser.d ./src/arg_parser.o ./src/arg_validity_check.d ./src/arg_validity_check.o ./src/base64.d ./src/base64.o ./src/cfg.d ./src/cfg.o ./src/channel.d ./src/channel.o ./src/cjson.d ./src/cjson.o ./src/common.d ./src/common.o ./src/daemon.d ./src/daemon.o ./src/ddr.d ./src/ddr.o ./src/env_check.d ./src/env_check.o ./src/fatal.d ./src/fatal.o ./src/filebrowser.d ./src/filebrowser.o ./src/handle.d ./src/handle.o ./src/hashmap.d ./src/hashmap.o ./src/history.d ./src/history.o ./src/loader.d ./src/loader.o ./src/log.d ./src/log.o ./src/misc.d ./src/misc.o ./src/mutexs.d ./src/mutexs.o ./src/ntmp.d ./src/ntmp.o ./src/nttabs.d ./src/nttabs.o ./src/pcie.d ./src/pcie.o ./src/phy_mix.d ./src/phy_mix.o ./src/phy_ssh.d ./src/phy_ssh.o ./src/phy_tty.d ./src/phy_tty.o ./src/poller.d ./src/poller.o ./src/procmgr.d ./src/procmgr.o ./src/results.d ./src/results.o ./src/rmt_exec.d ./src/rmt_exec.o ./src/scanner.d ./src/scanner.o ./src/server.d ./src/server.o ./src/setproctitle.d ./src/setproctitle.o ./src/shmlst.d ./src/shmlst.o ./src/ssh_tst.d ./src/ssh_tst.o ./src/str.d ./src/str.o ./src/tpool.d ./src/tpool.o

.PHONY: clean-src

