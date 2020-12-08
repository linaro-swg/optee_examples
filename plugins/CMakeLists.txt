project (optee_example_plugins C)

set (SRC host/main.c)

add_executable (${PROJECT_NAME} ${SRC})

target_include_directories(${PROJECT_NAME}
			   PRIVATE ta/include
			   PRIVATE include)

target_compile_definitions (${PROJECT_NAME}
	PRIVATE -DBINARY_PREFIX="TEE-EXMPL"
)

target_link_libraries (${PROJECT_NAME}
			   PRIVATE teec)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})

add_subdirectory (syslog)
