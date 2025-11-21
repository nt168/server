################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/prompt/choices.c \
../src/prompt/fzy.c \
../src/prompt/match.c \
../src/prompt/options.c \
../src/prompt/tty.c \
../src/prompt/tty_interface.c 

C_DEPS += \
./src/prompt/choices.d \
./src/prompt/fzy.d \
./src/prompt/match.d \
./src/prompt/options.d \
./src/prompt/tty.d \
./src/prompt/tty_interface.d 

OBJS += \
./src/prompt/choices.o \
./src/prompt/fzy.o \
./src/prompt/match.o \
./src/prompt/options.o \
./src/prompt/tty.o \
./src/prompt/tty_interface.o 


# Each subdirectory must supply rules for building sources it contributes
src/prompt/%.o: ../src/prompt/%.c src/prompt/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -DSQLITE_THREADSAFE=2 -I"../libdepds/libssh_0.9.3/include" -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


clean: clean-src-2f-prompt

clean-src-2f-prompt:
	-$(RM) ./src/prompt/choices.d ./src/prompt/choices.o ./src/prompt/fzy.d ./src/prompt/fzy.o ./src/prompt/match.d ./src/prompt/match.o ./src/prompt/options.d ./src/prompt/options.o ./src/prompt/tty.d ./src/prompt/tty.o ./src/prompt/tty_interface.d ./src/prompt/tty_interface.o

.PHONY: clean-src-2f-prompt

