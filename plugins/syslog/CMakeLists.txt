project (96bcf744-4f72-4866-bf1d-8634fd9c65e5.plugin C)

set (CFG_TEE_PLUGIN_LOAD_PATH "/usr/lib/tee-supplicant/plugins/")
set (CMAKE_SHARED_LIBRARY_PREFIX "")

add_library(${PROJECT_NAME} SHARED syslog_plugin.c)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CFG_TEE_PLUGIN_LOAD_PATH})
