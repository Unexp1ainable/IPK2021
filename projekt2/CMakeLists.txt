cmake_minimum_required(VERSION 3.0.0)
project(ipk-sniffer VERSION 0.1.0)

include(CTest)
enable_testing()

add_executable(ipk-sniffer ipk-sniffer.cpp sniffer_classes.cpp)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
