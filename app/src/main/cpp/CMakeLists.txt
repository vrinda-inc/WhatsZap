cmake_minimum_required(VERSION 3.22.1)

# Declares the name of the library
project("whatszap-native")

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

add_library(
    # Sets the name of the library.
    whatszap-native

    # Sets the library as a shared library.
    SHARED

    # Provides a relative path to your source file(s).
    native-lib.cpp
    file_monitor.cpp
    malware_scanner.cpp
)

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library(
    # Sets the name of the path variable.
    log-lib

    # Specifies the name of the NDK library that
    # you want CMake to locate.
    log
)

# Note: We removed OpenSSL dependency. MD5 hashing is now optional/simplified.
# libzip may need to be built separately or use a prebuilt version
# For now, we'll try to use system libraries if available

target_link_libraries(
    # Specifies the target library.
    whatszap-native

    # Links the target library to the log library
    # included in the NDK.
    ${log-lib}
    z
)

