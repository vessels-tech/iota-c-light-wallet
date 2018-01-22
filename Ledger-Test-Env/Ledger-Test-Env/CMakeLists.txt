cmake_minimum_required (VERSION 2.6)
project (IOTALedgerTest)
file(GLOB LedgerSRC
  "*.h"
  "*.c"
)
# this file has duplicate definitions?
list(REMOVE_ITEM LedgerSRC "${CMAKE_CURRENT_SOURCE_DIR}/add_seed_index_test.c")

# include stdint.h in every header, XCode seems to do so by default
set(CMAKE_REQUIRED_INCLUDES stdint.h)
if(MSVC)
    add_definitions(/FI"stdint.h")
else()
    # GCC or Clang
    add_definitions(-include stdint.h)
endif()

add_executable(IOTALedgerTest ${LedgerSRC})
