################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/phy_sql/phy_sql.c \
../src/phy_sql/sqlite3.c 

C_DEPS += \
./src/phy_sql/phy_sql.d \
./src/phy_sql/sqlite3.d 

OBJS += \
./src/phy_sql/phy_sql.o \
./src/phy_sql/sqlite3.o 


# Each subdirectory must supply rules for building sources it contributes
src/phy_sql/%.o: ../src/phy_sql/%.c src/phy_sql/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -DSQLITE_THREADSAFE=2 -I"../libdepds/libssh_0.9.3/include" -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


clean: clean-src-2f-phy_sql

clean-src-2f-phy_sql:
	-$(RM) ./src/phy_sql/phy_sql.d ./src/phy_sql/phy_sql.o ./src/phy_sql/sqlite3.d ./src/phy_sql/sqlite3.o

.PHONY: clean-src-2f-phy_sql

