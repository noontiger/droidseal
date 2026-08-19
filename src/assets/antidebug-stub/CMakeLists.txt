# DroidSeal opt-in anti-debug stub — self-developed, MIT.
# Minimal CMake build for the JNI detection library.

cmake_minimum_required(VERSION 3.18.1)
project(droidseal_antidebug C)

add_library(droidseal_antidebug SHARED droidseal_antidebug.c)
