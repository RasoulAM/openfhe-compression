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

# Utility rule file for allbinfheexamples.

# Include any custom commands dependencies for this target.
include src/binfhe/CMakeFiles/allbinfheexamples.dir/compiler_depend.make

# Include the progress variables for this target.
include src/binfhe/CMakeFiles/allbinfheexamples.dir/progress.make

allbinfheexamples: src/binfhe/CMakeFiles/allbinfheexamples.dir/build.make
.PHONY : allbinfheexamples

# Rule to build all files generated by this target.
src/binfhe/CMakeFiles/allbinfheexamples.dir/build: allbinfheexamples
.PHONY : src/binfhe/CMakeFiles/allbinfheexamples.dir/build

src/binfhe/CMakeFiles/allbinfheexamples.dir/clean:
	cd /home/r5akhava/diaa/openfhe-development/cmake-build-release/src/binfhe && $(CMAKE_COMMAND) -P CMakeFiles/allbinfheexamples.dir/cmake_clean.cmake
.PHONY : src/binfhe/CMakeFiles/allbinfheexamples.dir/clean

src/binfhe/CMakeFiles/allbinfheexamples.dir/depend:
	cd /home/r5akhava/diaa/openfhe-development/cmake-build-release && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/r5akhava/diaa/openfhe-development /home/r5akhava/diaa/openfhe-development/src/binfhe /home/r5akhava/diaa/openfhe-development/cmake-build-release /home/r5akhava/diaa/openfhe-development/cmake-build-release/src/binfhe /home/r5akhava/diaa/openfhe-development/cmake-build-release/src/binfhe/CMakeFiles/allbinfheexamples.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/binfhe/CMakeFiles/allbinfheexamples.dir/depend

