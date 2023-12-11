cmake_minimum_required(VERSION 3.10)
project(wetsocks VERSION 1.0.0 DESCRIPTION "Leaky Sockets Detector")

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "-g3")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

add_library(wetsocks SHARED wetsocks.cpp)
set_property(TARGET wetsocks PROPERTY CMAKE_CXX_STANDARD_REQUIRED ON)
set_property(TARGET wetsocks PROPERTY CXX_STANDARD 17)
target_link_libraries(wetsocks ${CMAKE_DL_LIBS})
