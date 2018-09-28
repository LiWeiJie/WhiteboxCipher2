
if (CMAKE_HOST_WIN32)
    set(WINDOWS 1)
elseif(CMAKE_HOST_APPLE)
    set(MACOS 1)
    SET(CMAKE_OSX_SYSROOT "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk")
elseif(CMAKE_HOST_UNIX)
    set(LINUX 1)
endif()


#1.cmake verson，指定cmake版本
cmake_minimum_required(VERSION 3.2)

#2.project name，指定项目的名称，一般和项目的文件夹名称对应
PROJECT(wbc2)

#3.head file path，头文件目录
INCLUDE_DIRECTORIES(include)
INCLUDE_DIRECTORIES(test)


#4.source directory，源文件目录
AUX_SOURCE_DIRECTORY(library LIB_SRCS)

# wbc2
AUX_SOURCE_DIRECTORY(library/wbc2 LIB_SRCS)

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


if (CMAKE_HOST_WIN32)
    set(WINDOWS 1)
elseif(CMAKE_HOST_APPLE)
    set(MACOS 1)
elseif(CMAKE_HOST_UNIX)
    set(LINUX 1)
endif()

# set AisinoSSL lib
FIND_LIBRARY(AISINOSSL_LIB AisinoSSL lib NO_DEFAULT_PATH)
message(${AISINOSSL_LIB})

ADD_LIBRARY(${BUILD_NAME} SHARED ${LIB_SRCS})
TARGET_LINK_LIBRARIES(${BUILD_NAME} ${AISINOSSL_LIB})

ADD_EXECUTABLE(${TEST_EXEC_NAME} ${TEST_EXEC}  )
TARGET_LINK_LIBRARIES(${TEST_EXEC_NAME} ${AISINOSSL_LIB} ${BUILD_NAME})

# TARGET_LINK_LIBRARIES(${TEST_EXEC_NAME} ${NTL_LIB} ${GMP_DIRS} ${Boost_LIBRARIES})



