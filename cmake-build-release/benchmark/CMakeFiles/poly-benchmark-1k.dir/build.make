# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.23

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/r5akhava/.cache/JetBrains/RemoteDev/dist/68305831d57ea_CLion-2022.2.4/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /home/r5akhava/.cache/JetBrains/RemoteDev/dist/68305831d57ea_CLion-2022.2.4/bin/cmake/linux/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/r5akhava/diaa/openfhe-development

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/r5akhava/diaa/openfhe-development/cmake-build-release

# Include any dependencies generated for this target.
include benchmark/CMakeFiles/poly-benchmark-1k.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include benchmark/CMakeFiles/poly-benchmark-1k.dir/compiler_depend.make

# Include the progress variables for this target.
include benchmark/CMakeFiles/poly-benchmark-1k.dir/progress.make

# Include the compile flags for this target's objects.
include benchmark/CMakeFiles/poly-benchmark-1k.dir/flags.make

benchmark/CMakeFiles/poly-benchmark-1k.dir/src/poly-benchmark-1k.cpp.o: benchmark/CMakeFiles/poly-benchmark-1k.dir/flags.make
benchmark/CMakeFiles/poly-benchmark-1k.dir/src/poly-benchmark-1k.cpp.o: ../benchmark/src/poly-benchmark-1k.cpp
benchmark/CMakeFiles/poly-benchmark-1k.dir/src/poly-benchmark-1k.cpp.o: benchmark/CMakeFiles/poly-benchmark-1k.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/r5akhava/diaa/openfhe-development/cmake-build-release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object benchmark/CMakeFiles/poly-benchmark-1k.dir/src/poly-benchmark-1k.cpp.o"
	cd /home/r5akhava/diaa/openfhe-development/cmake-build-release/benchmark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT benchmark/CMakeFiles/poly-benchmark-1k.dir/src/poly-benchmark-1k.cpp.o -MF CMakeFiles/poly-benchmark-1k.dir/src/poly-benchmark-1k.cpp.o.d -o CMakeFiles/poly-benchmark-1k.dir/src/poly-benchmark-1k.cpp.o -c /home/r5akhava/diaa/openfhe-development/benchmark/src/poly-benchmark-1k.cpp

benchmark/CMakeFiles/poly-benchmark-1k.dir/src/poly-benchmark-1k.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/poly-benchmark-1k.dir/src/poly-benchmark-1k.cpp.i"
	cd /home/r5akhava/diaa/openfhe-development/cmake-build-release/benchmark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/r5akhava/diaa/openfhe-development/benchmark/src/poly-benchmark-1k.cpp > CMakeFiles/poly-benchmark-1k.dir/src/poly-benchmark-1k.cpp.i

benchmark/CMakeFiles/poly-benchmark-1k.dir/src/poly-benchmark-1k.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/poly-benchmark-1k.dir/src/poly-benchmark-1k.cpp.s"
	cd /home/r5akhava/diaa/openfhe-development/cmake-build-release/benchmark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/r5akhava/diaa/openfhe-development/benchmark/src/poly-benchmark-1k.cpp -o CMakeFiles/poly-benchmark-1k.dir/src/poly-benchmark-1k.cpp.s

# Object files for target poly-benchmark-1k
poly__benchmark__1k_OBJECTS = \
"CMakeFiles/poly-benchmark-1k.dir/src/poly-benchmark-1k.cpp.o"

# External object files for target poly-benchmark-1k
poly__benchmark__1k_EXTERNAL_OBJECTS =

bin/benchmark/poly-benchmark-1k: benchmark/CMakeFiles/poly-benchmark-1k.dir/src/poly-benchmark-1k.cpp.o
bin/benchmark/poly-benchmark-1k: benchmark/CMakeFiles/poly-benchmark-1k.dir/build.make
bin/benchmark/poly-benchmark-1k: lib/libOPENFHEpke.so.1.0.1
bin/benchmark/poly-benchmark-1k: lib/libOPENFHEbinfhe.so.1.0.1
bin/benchmark/poly-benchmark-1k: lib/libOPENFHEcore.so.1.0.1
bin/benchmark/poly-benchmark-1k: /home/r5akhava/diaa/pailliercryptolib/build/lib/libipcl.so.1.1.4
bin/benchmark/poly-benchmark-1k: lib/libbenchmark.a
bin/benchmark/poly-benchmark-1k: /usr/lib/x86_64-linux-gnu/libssl.so
bin/benchmark/poly-benchmark-1k: /usr/lib/x86_64-linux-gnu/libcrypto.so
bin/benchmark/poly-benchmark-1k: /usr/lib/gcc/x86_64-linux-gnu/11/libgomp.so
bin/benchmark/poly-benchmark-1k: /usr/lib/x86_64-linux-gnu/libpthread.a
bin/benchmark/poly-benchmark-1k: /usr/lib/x86_64-linux-gnu/librt.a
bin/benchmark/poly-benchmark-1k: benchmark/CMakeFiles/poly-benchmark-1k.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/r5akhava/diaa/openfhe-development/cmake-build-release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable ../bin/benchmark/poly-benchmark-1k"
	cd /home/r5akhava/diaa/openfhe-development/cmake-build-release/benchmark && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/poly-benchmark-1k.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
benchmark/CMakeFiles/poly-benchmark-1k.dir/build: bin/benchmark/poly-benchmark-1k
.PHONY : benchmark/CMakeFiles/poly-benchmark-1k.dir/build

benchmark/CMakeFiles/poly-benchmark-1k.dir/clean:
	cd /home/r5akhava/diaa/openfhe-development/cmake-build-release/benchmark && $(CMAKE_COMMAND) -P CMakeFiles/poly-benchmark-1k.dir/cmake_clean.cmake
.PHONY : benchmark/CMakeFiles/poly-benchmark-1k.dir/clean

benchmark/CMakeFiles/poly-benchmark-1k.dir/depend:
	cd /home/r5akhava/diaa/openfhe-development/cmake-build-release && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/r5akhava/diaa/openfhe-development /home/r5akhava/diaa/openfhe-development/benchmark /home/r5akhava/diaa/openfhe-development/cmake-build-release /home/r5akhava/diaa/openfhe-development/cmake-build-release/benchmark /home/r5akhava/diaa/openfhe-development/cmake-build-release/benchmark/CMakeFiles/poly-benchmark-1k.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : benchmark/CMakeFiles/poly-benchmark-1k.dir/depend

