cmake_minimum_required(VERSION 3.21)
project(ffl_gnutls VERSION 0.1.0 LANGUAGES C)

set(FFL_GNUTLS_PROVIDER "system" CACHE STRING "GnuTLS provider: system or prefix")
set_property(CACHE FFL_GNUTLS_PROVIDER PROPERTY STRINGS system prefix)
set(FFL_GNUTLS_ROOT "" CACHE PATH "Prefix containing GnuTLS and its pkg-config metadata")
option(FFL_GNUTLS_STATIC "Link GnuTLS and its transitive dependencies statically" OFF)

find_package(Python REQUIRED COMPONENTS Interpreter Development.Module)
find_package(PkgConfig REQUIRED)

if(FFL_GNUTLS_PROVIDER STREQUAL "prefix")
    if(NOT FFL_GNUTLS_ROOT)
        message(FATAL_ERROR "FFL_GNUTLS_ROOT is required when FFL_GNUTLS_PROVIDER=prefix")
    endif()
    if(WIN32)
        set(_fflPkgConfigSeparator ";")
    else()
        set(_fflPkgConfigSeparator ":")
    endif()
    set(ENV{PKG_CONFIG_PATH}
        "${FFL_GNUTLS_ROOT}/lib/pkgconfig${_fflPkgConfigSeparator}${FFL_GNUTLS_ROOT}/lib64/pkgconfig${_fflPkgConfigSeparator}$ENV{PKG_CONFIG_PATH}")
elseif(NOT FFL_GNUTLS_PROVIDER STREQUAL "system")
    message(FATAL_ERROR "FFL_GNUTLS_PROVIDER must be system or prefix")
endif()

pkg_check_modules(GNUTLS REQUIRED IMPORTED_TARGET gnutls>=3.8.4)

Python_add_library(_ffl_gnutls MODULE WITH_SOABI
    native/crypto_core.c
    native/python_module.c
)
target_compile_features(_ffl_gnutls PRIVATE c_std_11)
target_include_directories(_ffl_gnutls PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/native")

if(FFL_GNUTLS_STATIC)
    target_include_directories(_ffl_gnutls PRIVATE ${GNUTLS_STATIC_INCLUDE_DIRS})
    target_link_directories(_ffl_gnutls PRIVATE ${GNUTLS_STATIC_LIBRARY_DIRS})
    target_link_libraries(_ffl_gnutls PRIVATE ${GNUTLS_STATIC_LIBRARIES})
    target_link_options(_ffl_gnutls PRIVATE ${GNUTLS_STATIC_LDFLAGS_OTHER})
else()
    target_link_libraries(_ffl_gnutls PRIVATE PkgConfig::GNUTLS)
endif()

set_target_properties(_ffl_gnutls PROPERTIES
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)
if(MSVC)
    target_compile_options(_ffl_gnutls PRIVATE /W4)
else()
    target_compile_options(_ffl_gnutls PRIVATE -Wall -Wextra -Wpedantic)
endif()

install(TARGETS _ffl_gnutls LIBRARY DESTINATION . RUNTIME DESTINATION .)
