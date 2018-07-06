set(PCAPSHIM_SOVERSION_MAJOR "0")
set(PCAPSHIM_SOVERSION "0.1.0")

file(GLOB pcapshim_src "*.cpp")
add_library(pcapshim SHARED ${pcapshim_src})
set_property(TARGET pcapshim PROPERTY SOVERSION "${PCAPSHIM_SOVERSION_MAJOR}")
set_property(TARGET pcapshim PROPERTY VERSION "${PCAPSHIM_SOVERSION}")
target_include_directories(pcapshim PRIVATE
    ${RPCLIB_INCLUDE_DIR} 
    ${COMMON_INCLUDE_DIR}
)
target_link_libraries(pcapshim 
    common 
    ${RPCLIB_LIBS} 
    ${PTHREAD_LIBRARY} 
    dl
)
add_executable(shim-test shim-test.cpp)
target_link_libraries(shim-test pcap rpc)
