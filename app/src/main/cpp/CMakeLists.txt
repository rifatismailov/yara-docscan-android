cmake_minimum_required(VERSION 3.22.1)
project(yaradocscan C)

# The YARA + DocScan sources come from the git submodule at the repository root.
set(YARA_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../../../../yara-docscan)
get_filename_component(YARA_ROOT ${YARA_ROOT} ABSOLUTE)
set(LY ${YARA_ROOT}/libyara)

if(NOT EXISTS ${LY}/libyara.c)
  message(FATAL_ERROR "yara-docscan submodule is missing: run `git submodule update --init`")
endif()

# Same module set as the Windows build (windows/vs2019/libyara): the vendor rules need hash, dotnet and
# pe.imphash / pe.signatures (authenticode), all of which need OpenSSL. cuckoo is left out (needs
# jansson; no rule imports it).
find_package(openssl REQUIRED CONFIG)

set(YARA_MODULES
  ${LY}/modules/tests/tests.c
  ${LY}/modules/elf/elf.c
  ${LY}/modules/math/math.c
  ${LY}/modules/time/time.c
  ${LY}/modules/pe/pe.c
  ${LY}/modules/pe/pe_utils.c
  ${LY}/modules/pe/authenticode-parser/authenticode.c
  ${LY}/modules/pe/authenticode-parser/certificate.c
  ${LY}/modules/pe/authenticode-parser/countersignature.c
  ${LY}/modules/pe/authenticode-parser/helper.c
  ${LY}/modules/pe/authenticode-parser/structs.c
  ${LY}/modules/hash/hash.c
  ${LY}/modules/dotnet/dotnet.c
  ${LY}/modules/dex/dex.c          # Android: vendor rules over classes.dex
  ${LY}/modules/console/console.c
  ${LY}/modules/string/string.c
  ${LY}/modules/docscan/docscan.c
  ${LY}/modules/docscan/magic.c
  ${LY}/modules/docscan/search.c
  ${LY}/modules/docscan/inspect_rtf.c
  ${LY}/modules/docscan/inspect_pdf.c
  ${LY}/modules/docscan/miniz.c
  ${LY}/modules/docscan/zip.c
  ${LY}/modules/docscan/rels.c
  ${LY}/modules/docscan/inspect_ooxml.c
  ${LY}/modules/docscan/cfb.c
  ${LY}/modules/docscan/oleobj.c
  ${LY}/modules/docscan/text.c
  ${LY}/modules/docscan/critical.c
  ${LY}/modules/docscan/msovba.c
  ${LY}/modules/docscan/vba.c
  ${LY}/modules/docscan/inspect_ole.c
  ${LY}/modules/docscan/lnk.c
  ${LY}/modules/docscan/disarm.c
)

# Lexers / grammars are taken pre-generated from the repository (no flex/bison needed).
set(YARA_CORE
  ${LY}/grammar.c
  ${LY}/ahocorasick.c
  ${LY}/arena.c
  ${LY}/atoms.c
  ${LY}/base64.c
  ${LY}/bitmask.c
  ${LY}/compiler.c
  ${LY}/endian.c
  ${LY}/exec.c
  ${LY}/exefiles.c
  ${LY}/filemap.c
  ${LY}/hash.c
  ${LY}/hex_grammar.c
  ${LY}/hex_lexer.c
  ${LY}/lexer.c
  ${LY}/libyara.c
  ${LY}/mem.c
  ${LY}/modules.c
  ${LY}/notebook.c
  ${LY}/object.c
  ${LY}/parser.c
  ${LY}/proc.c
  ${LY}/re.c
  ${LY}/re_grammar.c
  ${LY}/re_lexer.c
  ${LY}/rules.c
  ${LY}/scan.c
  ${LY}/scanner.c
  ${LY}/simple_str.c
  ${LY}/sizedstr.c
  ${LY}/stack.c
  ${LY}/stopwatch.c
  ${LY}/strutils.c
  ${LY}/stream.c
  ${LY}/tlshc/tlsh.c
  ${LY}/tlshc/tlsh_impl.c
  ${LY}/tlshc/tlsh_util.c
  ${LY}/threading.c
  ${LY}/proc/none.c     # process memory scanning is not needed on Android
)

add_library(yara STATIC ${YARA_CORE} ${YARA_MODULES})
target_include_directories(yara PUBLIC ${LY}/include PRIVATE ${LY})
target_link_libraries(yara PUBLIC openssl::crypto)
target_compile_definitions(yara PRIVATE
  _GNU_SOURCE
  BUCKETS_128=1
  CHECKSUM_1B=1
  HAVE_SCAN_PROC_IMPL=0
  USE_NO_PROC
  HAVE_LIBCRYPTO=1
  HASH_MODULE=1
  DOTNET_MODULE=1
  DEX_MODULE=1
  HAVE_CLOCK_GETTIME=1
  HAVE_STDBOOL_H=1
  HAVE_TIMEGM=1
  HAVE_MEMMEM=1
  HAVE_STRLCPY=1
  HAVE_STRLCAT=1
)
target_compile_options(yara PRIVATE -O2 -fvisibility=hidden -w)

# JNI bridge: the Android counterpart of the docscan parts of cli/yara.c.
add_library(yaradocscan SHARED docscan_jni.c)
target_link_libraries(yaradocscan PRIVATE yara log)
target_compile_options(yaradocscan PRIVATE -O2 -Wall)
# 16 KB page size support (required for new apps on Google Play since Android 15).
target_link_options(yaradocscan PRIVATE "-Wl,-z,max-page-size=16384")
