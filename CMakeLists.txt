cmake_minimum_required (VERSION 3.2)
project (optee_examples C)

# https://cmake.org/Wiki/CMake_Useful_Variables
set (CMAKE_TOOLCHAIN_FILE CMakeToolchain.txt)

include(GNUInstallDirs)

add_compile_options (-Wall)
#add_compile_options (
#	-Wall -Wbad-function-cast -Wcast-align
#	-Werror-implicit-function-declaration -Wextra
#	-Wfloat-equal -Wformat-nonliteral -Wformat-security
#	-Wformat=2 -Winit-self -Wmissing-declarations
#	-Wmissing-format-attribute -Wmissing-include-dirs
#	-Wmissing-noreturn -Wmissing-prototypes -Wnested-externs
#	-Wpointer-arith -Wshadow -Wstrict-prototypes
#	-Wswitch-default -Wunsafe-loop-optimizations
#	-Wwrite-strings -Werror -fPIC
#)

find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
	set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
	set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif(CCACHE_FOUND)


# TA must be built from TA SDK based on GNU Makefiles and not compatible with
# a CMake build process. Using this macro. Unless -DBUILD_OPTEE_TAS=n, TAs
# are built.
#
# Helper macro define_ta_source_dir() ease integzation of TA source trees.
#
# Using macro define_ta_source_dir(TA_NAME TA_SOURCE_PATH)
# - 'make all' will build TA from source
# - 'make install' will install TA binary file (*.ta) in /lib/optee_armtz
# - 'make clean' will clean TA build directory
if (NOT BUILD_OPTEE_TAS)
	set (BUILD_OPTEE_TAS y)
endif ()

macro (define_ta_source_dir TA_NAME TA_SOURCE_PATH)

	if (BUILD_OPTEE_TAS)
	project (optee_example_${TA_NAME}_ta)

	set_directory_properties(
		PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${CMAKE_CURRENT_SOURCE_DIR}/${TA_SOURCE_PATH}/out"
		)

	add_custom_target (
		build-optee_example_${TA_NAME}_ta ALL
		)

	add_custom_command (
		TARGET build-optee_example_${TA_NAME}_ta
		COMMAND make -C ${TA_SOURCE_PATH} O=${CMAKE_CURRENT_SOURCE_DIR}/${TA_SOURCE_PATH}/out TA_DEV_KIT_DIR=${OPTEE_EXAMPLES_SDK} all
		COMMENT "Compiling Trusted Applications"
		VERBATIM
		)

	install (
		DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${TA_SOURCE_PATH}/out/ DESTINATION /lib/optee_armtz
	        FILES_MATCHING PATTERN "out/*.ta"
		)
	endif () # BUILD_OPTEE_TAS

endmacro ()

file(GLOB dirs *)
foreach(dir ${dirs})
	if(EXISTS ${dir}/CMakeLists.txt)
		add_subdirectory(${dir})
	endif()
endforeach()
