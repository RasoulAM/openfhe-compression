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
include benchmark/CMakeFiles/VectorMath.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include benchmark/CMakeFiles/VectorMath.dir/compiler_depend.make

# Include the progress variables for this target.
include benchmark/CMakeFiles/VectorMath.dir/progress.make

# Include the compile flags for this target's objects.
include benchmark/CMakeFiles/VectorMath.dir/flags.make

benchmark/CMakeFiles/VectorMath.dir/src/VectorMath.cpp.o: benchmark/CMakeFiles/VectorMath.dir/flags.make
benchmark/CMakeFiles/VectorMath.dir/src/VectorMath.cpp.o: ../benchmark/src/VectorMath.cpp
benchmark/CMakeFiles/VectorMath.dir/src/VectorMath.cpp.o: benchmark/CMakeFiles/VectorMath.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/r5akhava/diaa/openfhe-development/cmake-build-release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object benchmark/CMakeFiles/VectorMath.dir/src/VectorMath.cpp.o"
	cd /home/r5akhava/diaa/openfhe-development/cmake-build-release/benchmark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT benchmark/CMakeFiles/VectorMath.dir/src/VectorMath.cpp.o -MF CMakeFiles/VectorMath.dir/src/VectorMath.cpp.o.d -o CMakeFiles/VectorMath.dir/src/VectorMath.cpp.o -c /home/r5akhava/diaa/openfhe-development/benchmark/src/VectorMath.cpp

benchmark/CMakeFiles/VectorMath.dir/src/VectorMath.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/VectorMath.dir/src/VectorMath.cpp.i"
	cd /home/r5akhava/diaa/openfhe-development/cmake-build-release/benchmark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/r5akhava/diaa/openfhe-development/benchmark/src/VectorMath.cpp > CMakeFiles/VectorMath.dir/src/VectorMath.cpp.i

benchmark/CMakeFiles/VectorMath.dir/src/VectorMath.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/VectorMath.dir/src/VectorMath.cpp.s"
	cd /home/r5akhava/diaa/openfhe-development/cmake-build-release/benchmark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/r5akhava/diaa/openfhe-development/benchmark/src/VectorMath.cpp -o CMakeFiles/VectorMath.dir/src/VectorMath.cpp.s

# Object files for target VectorMath
VectorMath_OBJECTS = \
"CMakeFiles/VectorMath.dir/src/VectorMath.cpp.o"

# External object files for target VectorMath
VectorMath_EXTERNAL_OBJECTS =

bin/benchmark/VectorMath: benchmark/CMakeFiles/VectorMath.dir/src/VectorMath.cpp.o
bin/benchmark/VectorMath: benchmark/CMakeFiles/VectorMath.dir/build.make
bin/benchmark/VectorMath: lib/libOPENFHEpke.so.1.0.1
bin/benchmark/VectorMath: lib/libOPENFHEbinfhe.so.1.0.1
bin/benchmark/VectorMath: lib/libOPENFHEcore.so.1.0.1
bin/benchmark/VectorMath: /home/r5akhava/diaa/pailliercryptolib/build/lib/libipcl.so.1.1.4
bin/benchmark/VectorMath: lib/libbenchmark.a
bin/benchmark/VectorMath: /usr/lib/x86_64-linux-gnu/libssl.so
bin/benchmark/VectorMath: /usr/lib/x86_64-linux-gnu/libcrypto.so
bin/benchmark/VectorMath: /usr/lib/gcc/x86_64-linux-gnu/11/libgomp.so
bin/benchmark/VectorMath: /usr/lib/x86_64-linux-gnu/libpthread.a
bin/benchmark/VectorMath: /usr/lib/x86_64-linux-gnu/librt.a
bin/benchmark/VectorMath: benchmark/CMakeFiles/VectorMath.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/r5akhava/diaa/openfhe-development/cmake-build-release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable ../bin/benchmark/VectorMath"
	cd /home/r5akhava/diaa/openfhe-development/cmake-build-release/benchmark && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/VectorMath.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
benchmark/CMakeFiles/VectorMath.dir/build: bin/benchmark/VectorMath
.PHONY : benchmark/CMakeFiles/VectorMath.dir/build

benchmark/CMakeFiles/VectorMath.dir/clean:
	cd /home/r5akhava/diaa/openfhe-development/cmake-build-release/benchmark && $(CMAKE_COMMAND) -P CMakeFiles/VectorMath.dir/cmake_clean.cmake
.PHONY : benchmark/CMakeFiles/VectorMath.dir/clean

benchmark/CMakeFiles/VectorMath.dir/depend:
	cd /home/r5akhava/diaa/openfhe-development/cmake-build-release && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/r5akhava/diaa/openfhe-development /home/r5akhava/diaa/openfhe-development/benchmark /home/r5akhava/diaa/openfhe-development/cmake-build-release /home/r5akhava/diaa/openfhe-development/cmake-build-release/benchmark /home/r5akhava/diaa/openfhe-development/cmake-build-release/benchmark/CMakeFiles/VectorMath.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : benchmark/CMakeFiles/VectorMath.dir/depend

