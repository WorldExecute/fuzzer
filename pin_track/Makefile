##############################################################
#
#                   DO NOT EDIT THIS FILE!
#
##############################################################

TARGET ?= intel64

# If the tool is built out of the kit, PIN_ROOT must be specified in the make invocation and point to the kit root.
ifdef PIN_ROOT
CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
else
CONFIG_ROOT := ../Config
endif

CUR_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
LIBDFT_PATH ?=  $(shell dirname ${CUR_DIR})/lib/libdft64
# LIBDFT_PATH := ${CUR_DIR}/../lib/libdft64


include $(CONFIG_ROOT)/makefile.config
include makefile.rules
include $(TOOLS_ROOT)/Config/makefile.default.rules

##############################################################
#
#                   DO NOT EDIT THIS FILE!
#
##############################################################
