cmake_minimum_required(VERSION 3.15)
project(CS453_2019_project)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)
include_directories(234747)
include_directories(cmake-build-debug)
include_directories(grading)
include_directories(include)
include_directories(playground)
include_directories(reference)
include_directories(template)

add_executable(CS453_2019_project
        234747/Makefile
        234747/stm_structures.h
        234747/tl2_utils.c
        234747/tl2_utils.h
        234747/tm.c
        234747/utils.c
        234747/utils.h
        cmake-build-debug/cmake_install.cmake
        cmake-build-debug/CMakeCache.txt
        cmake-build-debug/CS453_2019_project.cbp
        cmake-build-debug/Makefile
        grading/common.hpp
        grading/grading
        grading/grading.cpp
        grading/Makefile
        grading/transactional.hpp
        grading/workload.hpp
        include/tm.h
        include/tm.hpp
        playground/entrypoint.cpp
        playground/entrypoint.hpp
        playground/Makefile
        playground/playground
        playground/runner.cpp
        playground/runner.hpp
        reference/Makefile
        reference/tm.c
        template/Makefile
        template/tm.c
        README.md
        reference.so
        submit.py)
