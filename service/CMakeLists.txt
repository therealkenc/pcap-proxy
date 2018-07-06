if(WIN32)
set(WIN32_EXTRA_LIBS Iphlpapi.lib Ws2_32.lib)
endif()

add_executable(pcapsvrd service.cpp)
target_include_directories(pcapsvrd PRIVATE 
    ${COMMON_INCLUDE_DIR} 
    ${RPCLIB_INCLUDE_DIR} 
    ${PCAP_INCLUDE_DIR}
)
target_link_libraries(pcapsvrd 
    common 
    ${RPCLIB_LIBS} 
    ${PCAP_LIBRARY} 
    ${PTHREAD_LIBRARY}
    ${WIN32_EXTRA_LIBS}
)

