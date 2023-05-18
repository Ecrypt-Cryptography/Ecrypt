#
# Copyright (c) 2015 Cossack Labs Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LIBECCONNECT_A = libecconnect.a
LIBECCONNECT_SO = libecconnect.$(SHARED_EXT)
LIBECCONNECT_LINK = libecconnect.$(SHARED_EXT)

ifdef IS_LINUX
LIBECCONNECT_SO = libecconnect.$(SHARED_EXT).$(LIBRARY_SO_VERSION)
LIBECCONNECT_SO_LDFLAGS = -Wl,-soname,$(LIBECCONNECT_SO)
endif
ifdef IS_MACOS
LIBECCONNECT_SO = libecconnect.$(LIBRARY_SO_VERSION).$(SHARED_EXT)
endif
ifdef IS_MSYS
LIBECCONNECT_SO = msys-ecconnect-$(LIBRARY_SO_VERSION).$(SHARED_EXT)
LIBECCONNECT_LINK =
LIBECCONNECT_IMPORT = libecconnect.dll.a
LIBECCONNECT_SO_LDFLAGS = -Wl,-out-implib,$(BIN_PATH)/$(LIBECCONNECT_IMPORT)
endif

ECCONNECT_SOURCES = $(wildcard $(SRC_PATH)/ecconnect/*.c)
ECCONNECT_HEADERS += $(wildcard $(INC_PATH)/ecconnect/*.h)
ECCONNECT_HEADERS += $(wildcard $(SRC_PATH)/ecconnect/*.h)
ED25519_SOURCES = $(wildcard $(SRC_PATH)/ecconnect/ed25519/*.c)
ED25519_HEADERS = $(wildcard $(SRC_PATH)/ecconnect/ed25519/*.h)

ECCONNECT_SRC = $(ECCONNECT_SOURCES) $(ED25519_SOURCES) $(CRYPTO_ENGINE_SOURCES)

ECCONNECT_AUD_SRC += $(ECCONNECT_SOURCES) $(ED25519_SOURCES) $(CRYPTO_ENGINE_SOURCES)
ECCONNECT_AUD_SRC += $(ECCONNECT_HEADERS) $(ED25519_HEADERS) $(CRYPTO_ENGINE_HEADERS)

# Ignore ed25519 during code reformatting as it is 3rd-party code (and it breaks clang-tidy)
ECCONNECT_FMT_SRC += $(ECCONNECT_SOURCES) $(CRYPTO_ENGINE_SOURCES)
ECCONNECT_FMT_SRC += $(ECCONNECT_HEADERS) $(CRYPTO_ENGINE_HEADERS)

include $(CRYPTO_ENGINE)/ecconnect.mk

ECCONNECT_OBJ = $(patsubst %,$(OBJ_PATH)/%.o, $(ECCONNECT_SRC))

ECCONNECT_AUD = $(patsubst $(SRC_PATH)/%,$(AUD_PATH)/%, $(ECCONNECT_AUD_SRC))

FMT_FIXUP += $(patsubst %,$(OBJ_PATH)/%.fmt_fixup, $(ECCONNECT_FMT_SRC))
FMT_CHECK += $(patsubst %,$(OBJ_PATH)/%.fmt_check, $(ECCONNECT_FMT_SRC))

ECCONNECT_STATIC = $(BIN_PATH)/$(LIBECCONNECT_A)

$(ECCONNECT_OBJ): CFLAGS += -DECCONNECT_EXPORT
$(ECCONNECT_OBJ): CFLAGS += $(ECCONNECT_CRYPTO_ENGINE_CFLAGS)

# First build ecconnect library, then merge embedded crypto engine libs into it.
# On macOS this may cause warnings about files with no symbols in BoringSSL,
# suppress those warnings with some Bash wizardry.
$(BIN_PATH)/$(LIBECCONNECT_A): CMD = $(AR) rcs $@ $(filter %.o, $^) \
    && scripts/merge-static-libs.sh $@ $(filter %.a, $^) \
    $(if $(IS_MACOS),> >(grep -v 'has no symbols$$'))

# Make sure to build dependencies before objects. This is important in case
# of embedded BoringSSL with renamed symbols: they need to be renamed before
# ecconnect's objects are built against them.
$(ECCONNECT_OBJ): $(ECCONNECT_ENGINE_DEPS)

$(BIN_PATH)/$(LIBECCONNECT_A): $(ECCONNECT_OBJ) $(ECCONNECT_ENGINE_DEPS)
	@mkdir -p $(@D)
	@echo -n "link "
	@$(BUILD_CMD)

$(BIN_PATH)/$(LIBECCONNECT_SO): CMD = $(CC) -shared -o $@ $(filter %.o %a, $^) $(LDFLAGS) $(CRYPTO_ENGINE_LDFLAGS) $(LIBECCONNECT_SO_LDFLAGS)

$(BIN_PATH)/$(LIBECCONNECT_SO): $(ECCONNECT_OBJ) $(ECCONNECT_ENGINE_DEPS)
	@mkdir -p $(@D)
	@echo -n "link "
	@$(BUILD_CMD)
ifneq ($(LIBECCONNECT_SO),$(LIBECCONNECT_LINK))
	@ln -sf $(LIBECCONNECT_SO) $(BIN_PATH)/$(LIBECCONNECT_LINK)
endif

$(BIN_PATH)/libecconnect.pc:
	@mkdir -p $(BIN_PATH)
	@sed -e "s!%libdir%!$(libdir)!" \
	     -e "s!%includedir%!$(includedir)!" \
	     -e "s!%version%!$(VERSION)!" \
	     -e "s!%crypto-libs%!$(CRYPTO_ENGINE_LDFLAGS)!" \
	    $(SRC_PATH)/ecconnect/libecconnect.pc.in > $(BIN_PATH)/libecconnect.pc

install_ecconnect: $(BIN_PATH)/$(LIBECCONNECT_A) $(BIN_PATH)/$(LIBECCONNECT_SO) $(BIN_PATH)/libecconnect.pc
	@echo -n "install Ecconnect "
	@mkdir -p $(DESTDIR)$(includedir)/ecconnect
	@mkdir -p $(DESTDIR)$(pkgconfigdir)
ifdef IS_MSYS
	@mkdir -p $(DESTDIR)$(bindir)
endif
	@mkdir -p $(DESTDIR)$(libdir)
	@$(INSTALL_DATA) $(INC_PATH)/ecconnect/*.h              $(DESTDIR)$(includedir)/ecconnect
	@$(INSTALL_DATA) $(BIN_PATH)/libecconnect.pc            $(DESTDIR)$(pkgconfigdir)
	@$(INSTALL_DATA) $(BIN_PATH)/$(LIBECCONNECT_A)          $(DESTDIR)$(libdir)
ifdef IS_MSYS
	@$(INSTALL_PROGRAM) $(BIN_PATH)/$(LIBECCONNECT_SO)      $(DESTDIR)$(bindir)
else
	@$(INSTALL_PROGRAM) $(BIN_PATH)/$(LIBECCONNECT_SO)      $(DESTDIR)$(libdir)
endif
ifdef IS_MACOS
	@install_name_tool -id "$(libdir)/$(LIBECCONNECT_SO)" "$(DESTDIR)$(libdir)/$(LIBECCONNECT_SO)"
	@install_name_tool -change "$(BIN_PATH)/$(LIBECCONNECT_SO)" "$(libdir)/$(LIBECCONNECT_SO)" "$(DESTDIR)$(libdir)/$(LIBECCONNECT_SO)"
endif
ifneq ($(LIBECCONNECT_IMPORT),)
	@$(INSTALL_DATA) $(BIN_PATH)/$(LIBECCONNECT_IMPORT)     $(DESTDIR)$(libdir)
endif
ifneq ($(LIBECCONNECT_LINK),)
	@ln -sf $(LIBECCONNECT_SO)                              $(DESTDIR)$(libdir)/$(LIBECCONNECT_LINK)
endif
	@$(PRINT_OK_)

uninstall_ecconnect:
	@echo -n "uninstall ecconnect "
	@rm -rf $(DESTDIR)$(includedir)/ecconnect
	@rm  -f $(DESTDIR)$(pkgconfigdir)/libecconnect.pc
	@rm  -f $(DESTDIR)$(libdir)/$(LIBECCONNECT_A)
ifdef IS_MSYS
	@rm  -f $(DESTDIR)$(bindir)/$(LIBECCONNECT_SO)
	@rm  -f $(DESTDIR)$(libdir)/$(LIBECCONNECT_IMPORT)
else
	@rm  -f $(DESTDIR)$(libdir)/$(LIBECCONNECT_SO)
	@rm  -f $(DESTDIR)$(libdir)/$(LIBECCONNECT_LINK)
endif
	@$(PRINT_OK_)
