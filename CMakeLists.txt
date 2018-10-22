
#1.cmake verson，指定cmake版本
cmake_minimum_required(VERSION 3.2)

option(BUILD_TARGET "target platform" OFF)

if (CMAKE_HOST_WIN32)
    set(WINDOWS 1)
    set(build_os WINDOWS)

elseif(CMAKE_HOST_APPLE)
    set(MACOS 1)
    set(build_os macOS)
    SET(CMAKE_OSX_SYSROOT "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk")
elseif(CMAKE_HOST_UNIX)
    set(LINUX 1)
    set(build_os linux)
endif()

IF(BUILD_TARGET)
    message("\nBuild: ${BUILD_TARGET}")
ELSE()
    SET(BUILD_TARGET ${build_os})
    message("\nBuild: ${BUILD_TARGET}")
ENDIF()


IF(BUILD_TARGET STREQUAL macOS)
    add_definitions(-D__macOS__)
ENDIF()

IF(BUILD_TARGET STREQUAL win32)
    add_definitions(-D_WIN32)
ENDIF()

IF(BUILD_TARGET STREQUAL iOS)
    add_definitions(-D__iOS__)

    SET(CMD "xcrun -sdk iphoneos --show-sdk-path")
    EXEC_PROGRAM(${CMD} OUTPUT_VARIABLE iOS_SDK_PATH)
    SET(CMD "xcrun -sdk iphoneos --find clang")
    EXEC_PROGRAM(${CMD} OUTPUT_VARIABLE CLANG_PATH)
    set(CMAKE_C_COMPILER ${CLANG_PATH})
    #-F${iOS_SDK_PATH}/System/Library/Frameworks
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Os -isysroot ${iOS_SDK_PATH} -Wunused-command-line-argument -arch arm64 -arch armv7 -miphoneos-version-min=8.0 -fembed-bitcode")
    message("CMAKE_C_COMPILER: ${CMAKE_C_COMPILER}")
    message("CMAKE_C_FLAGS: ${CMAKE_C_FLAGS}")
ENDIF()

IF(BUILD_TARGET STREQUAL Android)
    add_definitions(-D__ANDROID__)

    message(FATAL_ERROR
    "Finished to generate <ml_config.h>! \n"
    "If you want to compile, please run 'ndk-build NDK_PROJECT_PATH=./ NDK_APPLICATION_MK=./Application.mk'."
    )
ENDIF()


#2.project name，指定项目的名称，一般和项目的文件夹名称对应
PROJECT(wbc2)


#3.head file path，头文件目录
INCLUDE_DIRECTORIES(include)
INCLUDE_DIRECTORIES(test)
find_package(JNI REQUIRED)
include_directories(${JAVA_INCLUDE_PATH})
include_directories(${JAVA_INCLUDE_PATH2})

#4.source directory，源文件目录
AUX_SOURCE_DIRECTORY(library LIB_SRCS)

# wbc2
AUX_SOURCE_DIRECTORY(library/wbc2 LIB_SRCS)

# feistalBox 
AUX_SOURCE_DIRECTORY(library/feistalBox LIB_SRCS)

# jni
AUX_SOURCE_DIRECTORY(library/jni LIB_SRCS)


# TEST 
AUX_SOURCE_DIRECTORY(. TEST_EXEC)
AUX_SOURCE_DIRECTORY(test TEST_EXEC)

# set name for build
SET(BUILD_NAME ${PROJECT_NAME})
# SET(BUILD_TEST_NAME ${PROJECT_NAME}_TEST)
SET(TEST_EXEC_NAME ${PROJECT_NAME}_MAIN)

SET(CXXFLAGS $ENV{CXXFLAGS})

set(CMAKE_CXX_FLAGS "-stdlib=libc++")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -O0 -g3")

#add_compile_options(-std=c11)

SET(CMAKE_BUILD_TYPE "Debug")
SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g2 -ggdb")
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

# SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -Os -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS10.3.sdk -F/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS10.3.sdk/System/Library/Frameworks -arch arm64 -arch armv7 -miphoneos-version-min=8.0 -flto")


# set(macOS_M4RI ON)
# set(ANDROID_M4RI ON)
# 

#6.add executable file，添加要编译的可执行文件
if (False) 
    message(${TEST_EXEC_NAME})
    message(${LIB_SRCS})
    message(${TEST_EXEC})
endif()


if (${BUILD_TARGET} STREQUAL win32)
    set(PlatformsLib lib/win32)
elseif(${BUILD_TARGET} STREQUAL macOS)
    set(PlatformsLib lib/macOS)
elseif(${BUILD_TARGET} STREQUAL linux)
    set(PlatformsLib lib/linux)
elseif(${BUILD_TARGET} STREQUAL android)
    set(PlatformsLib lib/android)
endif()

# set AisinoSSL lib
FIND_LIBRARY(AISINOSSL_LIB AisinoSSL ${PlatformsLib} NO_DEFAULT_PATH)
FIND_LIBRARY(Matrix_LIB MatrixLib ${PlatformsLib} NO_DEFAULT_PATH)
message(${AISINOSSL_LIB})
message(${Matrix_LIB})
if (${BUILD_TARGET} STREQUAL win32)
    FIND_LIBRARY(WS_LIB ws2_32 ${PlatformsLib})
    message(${WS_LIB})
endif()

ADD_LIBRARY(${BUILD_NAME} SHARED ${LIB_SRCS})
TARGET_LINK_LIBRARIES(${BUILD_NAME} ${AISINOSSL_LIB} ${Matrix_LIB} )
if (${BUILD_TARGET} STREQUAL win32)
    TARGET_LINK_LIBRARIES(${BUILD_NAME} ${WS_LIB} )
endif()

#ADD_EXECUTABLE(${TEST_EXEC_NAME} ${TEST_EXEC}  )
#TARGET_LINK_LIBRARIES(${TEST_EXEC_NAME}  ${BUILD_NAME})


