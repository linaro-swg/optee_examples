project (optee_example_veraison_attestation C)

set (SRC host/main.c host/client.c)

add_executable (${PROJECT_NAME} ${SRC})

# Define HOST_BUILD macro
add_definitions(-DHOST_BUILD)

target_include_directories(${PROJECT_NAME}
			   PRIVATE ta/include
			   PRIVATE include
			   PRIVATE $ENV{RUST_APICLIENT_DIR}/c-wrapper)

target_link_libraries (${PROJECT_NAME}
			   PRIVATE teec
			   PRIVATE $ENV{RUST_APICLIENT_DIR}/target/aarch64-unknown-linux-gnu/release/libveraison_apiclient_ffi.a)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -lm")

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
