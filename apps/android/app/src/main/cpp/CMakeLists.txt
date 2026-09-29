cmake_minimum_required(VERSION 3.22.1)
project(CompatForgeAndroid LANGUAGES CXX)

add_library(compatforge_jni SHARED native_probe.cpp)
target_compile_features(compatforge_jni PRIVATE cxx_std_17)
target_link_libraries(compatforge_jni PRIVATE dl)
