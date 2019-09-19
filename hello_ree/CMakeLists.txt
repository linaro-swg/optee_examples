project (optee_example_hello_ree C)

set (SRC host/main.c)

add_executable (${PROJECT_NAME} ${SRC})

target_include_directories(${PROJECT_NAME}
			   PRIVATE ta/include
			   PRIVATE include)

add_library(0e3ade56-96dc-44cf-9b52-2e6a06d84380 SHARED
            host/ree_dll.c)

target_link_libraries (${PROJECT_NAME} PRIVATE teec pthread 0e3ade56-96dc-44cf-9b52-2e6a06d84380)
target_include_directories(0e3ade56-96dc-44cf-9b52-2e6a06d84380 PRIVATE ta/include)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
