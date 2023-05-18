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

LIBECRYPT_A = libecrypt.a
LIBECRYPT_SO = libecrypt.$(SHARED_EXT)
LIBECRYPT_LINK = libecrypt.$(SHARED_EXT)

ifdef IS_LINUX
LIBECRYPT_SO = libecrypt.$(SHARED_EXT).$(LIBRARY_SO_VERSION)
LIBECRYPT_SO_LDFLAGS = -Wl,-soname,$(LIBECRYPT_SO)
endif
ifdef IS_MACOS
LIBECRYPT_SO = libecrypt.$(LIBRARY_SO_VERSION).$(SHARED_EXT)
endif
ifdef IS_MSYS
LIBECRYPT_SO = msys-ecrypt-$(LIBRARY_SO_VERSION).$(SHARED_EXT)
LIBECRYPT_LINK =
LIBECRYPT_IMPORT = libecrypt.dll.a
LIBECRYPT_SO_LDFLAGS = -Wl,-out-implib,$(BIN_PATH)/$(LIBECRYPT_IMPORT)
endif

ECRYPT_SOURCES = $(wildcard $(SRC_PATH)/ecrypt/*.c)
ECRYPT_HEADERS += $(wildcard $(INC_PATH)/ecrypt/*.h)
ECRYPT_HEADERS += $(wildcard $(SRC_PATH)/ecrypt/*.h)

ECRYPT_SRC = $(ECRYPT_SOURCES)
ECRYPT_AUD_SRC = $(ECRYPT_SOURCES) $(ECRYPT_HEADERS)
ECRYPT_FMT_SRC = $(ECRYPT_SOURCES) $(ECRYPT_HEADERS)

ECRYPT_OBJ = $(patsubst %,$(OBJ_PATH)/%.o, $(ECRYPT_SRC))

ECRYPT_AUD = $(patsubst $(SRC_PATH)/%,$(AUD_PATH)/%, $(ECRYPT_AUD_SRC))

FMT_FIXUP += $(patsubst %,$(OBJ_PATH)/%.fmt_fixup, $(ECRYPT_FMT_SRC))
FMT_CHECK += $(patsubst %,$(OBJ_PATH)/%.fmt_check, $(ECRYPT_FMT_SRC))

ECRYPT_STATIC = $(BIN_PATH)/$(LIBECRYPT_A) $(ECCONNECT_STATIC)

$(ECRYPT_OBJ): CFLAGS += -DECRYPT_EXPORT

ifneq ($(ECRYPT_DEFAULT_PBKDF2_ITERATIONS),)
$(ECRYPT_OBJ): CFLAGS += -DECRYPT_DEFAULT_PBKDF2_ITERATIONS=$(ECRYPT_DEFAULT_PBKDF2_ITERATIONS)
endif

$(BIN_PATH)/$(LIBECRYPT_A): CMD = $(AR) rcs $@ $(filter %.o, $^)

$(BIN_PATH)/$(LIBECRYPT_A): $(ECRYPT_OBJ)
	@mkdir -p $(@D)
	@echo -n "link "
	@$(BUILD_CMD)

$(BIN_PATH)/$(LIBECRYPT_SO): CMD = $(CC) -shared -o $@ $(filter %.o %.a, $^) $(LDFLAGS) -lecconnect $(LIBECRYPT_SO_LDFLAGS)

$(BIN_PATH)/$(LIBECRYPT_SO): $(BIN_PATH)/$(LIBECCONNECT_SO) $(ECRYPT_OBJ)
	@mkdir -p $(@D)
	@echo -n "link "
	@$(BUILD_CMD)
ifneq ($(LIBECRYPT_SO),$(LIBECRYPT_LINK))
	@ln -sf $(LIBECRYPT_SO) $(BIN_PATH)/$(LIBECRYPT_LINK)
endif

$(BIN_PATH)/libecrypt.pc:
	@mkdir -p $(BIN_PATH)
	@sed -e "s!%libdir%!$(libdir)!" \
	     -e "s!%includedir%!$(includedir)!" \
	     -e "s!%version%!$(VERSION)!" \
	    $(SRC_PATH)/ecrypt/libecrypt.pc.in > $(BIN_PATH)/libecrypt.pc

install_ecrypt: $(BIN_PATH)/$(LIBECRYPT_A) $(BIN_PATH)/$(LIBECRYPT_SO) $(BIN_PATH)/libecrypt.pc
	@echo -n "install Ecrypt "
	@mkdir -p $(DESTDIR)$(includedir)/ecrypt
	@mkdir -p $(DESTDIR)$(pkgconfigdir)
ifdef IS_MSYS
	@mkdir -p $(DESTDIR)$(bindir)
endif
	@mkdir -p $(DESTDIR)$(libdir)
	@$(INSTALL_DATA) $(INC_PATH)/ecrypt/*.h             $(DESTDIR)$(includedir)/ecrypt
	@$(INSTALL_DATA) $(BIN_PATH)/libecrypt.pc           $(DESTDIR)$(pkgconfigdir)
	@$(INSTALL_DATA) $(BIN_PATH)/$(LIBECRYPT_A)         $(DESTDIR)$(libdir)
ifdef IS_MSYS
	@$(INSTALL_PROGRAM) $(BIN_PATH)/$(LIBECRYPT_SO)     $(DESTDIR)$(bindir)
else
	@$(INSTALL_PROGRAM) $(BIN_PATH)/$(LIBECRYPT_SO)     $(DESTDIR)$(libdir)
endif
ifdef IS_MACOS
	@install_name_tool -id "$(libdir)/$(LIBECRYPT_SO)" "$(DESTDIR)$(libdir)/$(LIBECRYPT_SO)"
	@install_name_tool -change "$(BIN_PATH)/$(LIBECRYPT_SO)" "$(libdir)/$(LIBECRYPT_SO)" "$(DESTDIR)$(libdir)/$(LIBECRYPT_SO)"
	@install_name_tool -change "$(BIN_PATH)/$(LIBECCONNECT_SO)"  "$(libdir)/$(LIBECCONNECT_SO)"  "$(DESTDIR)$(libdir)/$(LIBECRYPT_SO)"
endif
ifneq ($(LIBECRYPT_IMPORT),)
	@$(INSTALL_DATA) $(BIN_PATH)/$(LIBECRYPT_IMPORT)    $(DESTDIR)$(libdir)
endif
ifneq ($(LIBECRYPT_LINK),)
	@ln -sf $(LIBECRYPT_SO)                             $(DESTDIR)$(libdir)/$(LIBECRYPT_LINK)
endif
	@$(PRINT_OK_)

uninstall_ecrypt:
	@echo -n "uninstall Ecrypt "
	@rm -rf $(DESTDIR)$(includedir)/ecrypt
	@rm  -f $(DESTDIR)$(pkgconfigdir)/libecrypt.pc
	@rm  -f $(DESTDIR)$(libdir)/$(LIBECRYPT_A)
ifdef IS_MSYS
	@rm  -f $(DESTDIR)$(bindir)/$(LIBECRYPT_SO)
	@rm  -f $(DESTDIR)$(libdir)/$(LIBECRYPT_IMPORT)
else
	@rm  -f $(DESTDIR)$(libdir)/$(LIBECRYPT_SO)
	@rm  -f $(DESTDIR)$(libdir)/$(LIBECRYPT_LINK)
endif
	@$(PRINT_OK_)
