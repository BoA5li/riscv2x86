cmake_minimum_required(VERSION 3.16)
project(riscv2x86 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

message(STATUS "C compiler: ${CMAKE_C_COMPILER}")
message(STATUS "CXX compiler: ${CMAKE_CXX_COMPILER}")
message(STATUS "CXX compiler version: ${CMAKE_CXX_COMPILER_VERSION}")

find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)

message(STATUS "Found LLVM package version: ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
message(STATUS "Using ClangConfig.cmake in: ${Clang_DIR}")
message(STATUS "LLVM include dirs: ${LLVM_INCLUDE_DIRS}")
message(STATUS "Clang include dirs: ${CLANG_INCLUDE_DIRS}")

if(LLVM_PACKAGE_VERSION VERSION_LESS 10 OR LLVM_PACKAGE_VERSION VERSION_GREATER_EQUAL 11)
  message(FATAL_ERROR "This project requires LLVM 10.x, but found ${LLVM_PACKAGE_VERSION}")
endif()

include_directories(${LLVM_INCLUDE_DIRS})
include_directories(${CLANG_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_definitions(${LLVM_DEFINITIONS})

# 只列出当前仓库中真实存在的源码
set(R2X_SOURCES
  src/main.cpp
  src/Classifier.cpp
  src/Rewriter.cpp
  src/RuleEngine.cpp
  src/PublicReplacement.cpp
  src/Report.cpp
  src/ReportLoad.cpp
  src/rules/BuiltinRules.cpp
  src/rules/AtomicRules.cpp
)

message(STATUS "R2X sources: ${R2X_SOURCES}")

add_executable(riscv2x86 ${R2X_SOURCES})

if(TARGET clang-cpp AND TARGET LLVM)
  message(STATUS "Link mode: monolithic imported targets (clang-cpp + LLVM)")
  target_link_libraries(riscv2x86
    PRIVATE
    clang-cpp
    LLVM
  )
else()
  message(STATUS "Link mode: component libraries (clang* + LLVMSupport)")

  llvm_map_components_to_libnames(LLVM_LIBS
    support
  )

  target_link_libraries(riscv2x86
    PRIVATE
    clangTooling
    clangFrontend
    clangSerialization
    clangDriver
    clangParse
    clangSema
    clangAnalysis
    clangEdit
    clangASTMatchers
    clangAST
    clangLex
    clangBasic
    ${LLVM_LIBS}
  )
endif()
