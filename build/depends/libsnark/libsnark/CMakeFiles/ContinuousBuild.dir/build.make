# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/mbadakhs/Project/zkSNARK/zupply-zkp

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/mbadakhs/Project/zkSNARK/zupply-zkp/build

# Utility rule file for ContinuousBuild.

# Include the progress variables for this target.
include depends/libsnark/libsnark/CMakeFiles/ContinuousBuild.dir/progress.make

depends/libsnark/libsnark/CMakeFiles/ContinuousBuild:
	cd /home/mbadakhs/Project/zkSNARK/zupply-zkp/build/depends/libsnark/libsnark && /usr/bin/ctest -D ContinuousBuild

ContinuousBuild: depends/libsnark/libsnark/CMakeFiles/ContinuousBuild
ContinuousBuild: depends/libsnark/libsnark/CMakeFiles/ContinuousBuild.dir/build.make

.PHONY : ContinuousBuild

# Rule to build all files generated by this target.
depends/libsnark/libsnark/CMakeFiles/ContinuousBuild.dir/build: ContinuousBuild

.PHONY : depends/libsnark/libsnark/CMakeFiles/ContinuousBuild.dir/build

depends/libsnark/libsnark/CMakeFiles/ContinuousBuild.dir/clean:
	cd /home/mbadakhs/Project/zkSNARK/zupply-zkp/build/depends/libsnark/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/ContinuousBuild.dir/cmake_clean.cmake
.PHONY : depends/libsnark/libsnark/CMakeFiles/ContinuousBuild.dir/clean

depends/libsnark/libsnark/CMakeFiles/ContinuousBuild.dir/depend:
	cd /home/mbadakhs/Project/zkSNARK/zupply-zkp/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/mbadakhs/Project/zkSNARK/zupply-zkp /home/mbadakhs/Project/zkSNARK/zupply-zkp/depends/libsnark/libsnark /home/mbadakhs/Project/zkSNARK/zupply-zkp/build /home/mbadakhs/Project/zkSNARK/zupply-zkp/build/depends/libsnark/libsnark /home/mbadakhs/Project/zkSNARK/zupply-zkp/build/depends/libsnark/libsnark/CMakeFiles/ContinuousBuild.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : depends/libsnark/libsnark/CMakeFiles/ContinuousBuild.dir/depend

