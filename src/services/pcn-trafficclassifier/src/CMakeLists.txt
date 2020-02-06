include(${PROJECT_SOURCE_DIR}/cmake/LoadFileAsVariable.cmake)

aux_source_directory(serializer SERIALIZER_SOURCES)
aux_source_directory(api API_SOURCES)
aux_source_directory(base BASE_SOURCES)
aux_source_directory(modules MODULES)

include_directories(serializer)
include_directories(modules)

if (NOT DEFINED POLYCUBE_STANDALONE_SERVICE OR POLYCUBE_STANDALONE_SERVICE)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(POLYCUBE libpolycube)
  include_directories(${POLYCUBE_INCLUDE_DIRS})
endif(NOT DEFINED POLYCUBE_STANDALONE_SERVICE OR POLYCUBE_STANDALONE_SERVICE)

# Needed to load files as variables
include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_library(pcn-trafficclassifier SHARED
  ${SERIALIZER_SOURCES}
  ${API_SOURCES}
  ${BASE_SOURCES}
  ${MODULES}
  TrafficClass.cpp
  Trafficclassifier.cpp
  Trafficclassifier-lib.cpp)

# load ebpf datapath code a variable
load_file_as_variable(pcn-trafficclassifier
  Selector_dp.c
  selector_code)
load_file_as_variable(pcn-trafficclassifier
  Matcher_dp.c
  matcher_code)
load_file_as_variable(pcn-trafficclassifier
  Parser_dp.c
  parser_code)
load_file_as_variable(pcn-trafficclassifier
  Tagger_dp.c
  tagger_code)

# load datamodel in a variable
load_file_as_variable(pcn-trafficclassifier
  ../datamodel/trafficclassifier.yang
  trafficclassifier_datamodel)

target_link_libraries(pcn-trafficclassifier ${POLYCUBE_LIBRARIES})

# Specify shared library install directory

set(CMAKE_INSTALL_LIBDIR /usr/lib)

install(
    TARGETS
    pcn-trafficclassifier
    DESTINATION
    "${CMAKE_INSTALL_LIBDIR}"
)
