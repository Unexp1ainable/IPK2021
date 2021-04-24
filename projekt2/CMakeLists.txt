cmake_minimum_required(VERSION 3.0.0)
project(ipk-sniffer VERSION 0.1.0)

include(CTest)
enable_testing()
include(FindPCAP.cmake)

add_executable(ipk-sniffer ipk-sniffer.cpp packet_lib.cpp sniffer_classes.cpp  )
target_link_libraries(ipk-sniffer ${PCAP_LIBRARY})

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
