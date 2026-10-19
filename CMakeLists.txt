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

add_library(riscv2x86_runtime STATIC
  runtime/riscv2x86_runtime_helpers.c
  runtime/riscv2x86_csr_runtime.c
)
set_target_properties(riscv2x86_runtime PROPERTIES POSITION_INDEPENDENT_CODE ON
  INTERPROCEDURAL_OPTIMIZATION FALSE)
target_include_directories(riscv2x86_runtime PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/runtime/include
)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(riscv2x86_runtime PRIVATE -fno-lto)
endif()
find_package(Python3 REQUIRED COMPONENTS Interpreter)
get_directory_property(_runtime_compile_definitions COMPILE_DEFINITIONS)
set(_runtime_definition_flags "")
foreach(_runtime_definition IN LISTS _runtime_compile_definitions)
  string(APPEND _runtime_definition_flags " -D${_runtime_definition}")
endforeach()
add_custom_target(riscv2x86_runtime_provenance ALL
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/experiment/write_runtime_build_manifest.py
    --root ${CMAKE_CURRENT_SOURCE_DIR}
    --archive $<TARGET_FILE:riscv2x86_runtime>
    --compiler ${CMAKE_C_COMPILER}
    --compiler-id ${CMAKE_C_COMPILER_ID}
    "--compiler-flags=${CMAKE_C_FLAGS} ${_runtime_definition_flags} $<$<CONFIG:Debug>:${CMAKE_C_FLAGS_DEBUG}>$<$<CONFIG:Release>:${CMAKE_C_FLAGS_RELEASE}>$<$<CONFIG:RelWithDebInfo>:${CMAKE_C_FLAGS_RELWITHDEBINFO}>$<$<CONFIG:MinSizeRel>:${CMAKE_C_FLAGS_MINSIZEREL}> -fno-lto"
    --output ${CMAKE_CURRENT_BINARY_DIR}/riscv2x86-runtime-build.json
  DEPENDS riscv2x86_runtime
  VERBATIM
)

if(TARGET clang-cpp AND TARGET LLVM)
  message(STATUS "Link mode: monolithic imported targets (clang-cpp + LLVM)")
  target_link_libraries(riscv2x86 PRIVATE clang-cpp LLVM)
else()
  message(STATUS "Link mode: component libraries (clang* + LLVMSupport)")
  llvm_map_components_to_libnames(LLVM_LIBS support)
  target_link_libraries(riscv2x86 PRIVATE
    clangTooling clangFrontend clangSerialization clangDriver clangParse
    clangSema clangAnalysis clangEdit clangASTMatchers clangAST clangLex
    clangBasic ${LLVM_LIBS}
  )
endif()
