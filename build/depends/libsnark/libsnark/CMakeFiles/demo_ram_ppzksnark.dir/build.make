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

# Include any dependencies generated for this target.
include depends/libsnark/libsnark/CMakeFiles/demo_ram_ppzksnark.dir/depend.make

# Include the progress variables for this target.
include depends/libsnark/libsnark/CMakeFiles/demo_ram_ppzksnark.dir/progress.make

# Include the compile flags for this target's objects.
include depends/libsnark/libsnark/CMakeFiles/demo_ram_ppzksnark.dir/flags.make

depends/libsnark/libsnark/CMakeFiles/demo_ram_ppzksnark.dir/zk_proof_systems/ppzksnark/ram_ppzksnark/examples/demo_ram_ppzksnark.cpp.o: depends/libsnark/libsnark/CMakeFiles/demo_ram_ppzksnark.dir/flags.make
depends/libsnark/libsnark/CMakeFiles/demo_ram_ppzksnark.dir/zk_proof_systems/ppzksnark/ram_ppzksnark/examples/demo_ram_ppzksnark.cpp.o: ../depends/libsnark/libsnark/zk_proof_systems/ppzksnark/ram_ppzksnark/examples/demo_ram_ppzksnark.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mbadakhs/Project/zkSNARK/zupply-zkp/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object depends/libsnark/libsnark/CMakeFiles/demo_ram_ppzksnark.dir/zk_proof_systems/ppzksnark/ram_ppzksnark/examples/demo_ram_ppzksnark.cpp.o"
	cd /home/mbadakhs/Project/zkSNARK/zupply-zkp/build/depends/libsnark/libsnark && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/demo_ram_ppzksnark.dir/zk_proof_systems/ppzksnark/ram_ppzksnark/examples/demo_ram_ppzksnark.cpp.o -c /home/mbadakhs/Project/zkSNARK/zupply-zkp/depends/libsnark/libsnark/zk_proof_systems/ppzksnark/ram_ppzksnark/examples/demo_ram_ppzksnark.cpp

depends/libsnark/libsnark/CMakeFiles/demo_ram_ppzksnark.dir/zk_proof_systems/ppzksnark/ram_ppzksnark/examples/demo_ram_ppzksnark.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/demo_ram_ppzksnark.dir/zk_proof_systems/ppzksnark/ram_ppzksnark/examples/demo_ram_ppzksnark.cpp.i"
	cd /home/mbadakhs/Project/zkSNARK/zupply-zkp/build/depends/libsnark/libsnark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/mbadakhs/Project/zkSNARK/zupply-zkp/depends/libsnark/libsnark/zk_proof_systems/ppzksnark/ram_ppzksnark/examples/demo_ram_ppzksnark.cpp > CMakeFiles/demo_ram_ppzksnark.dir/zk_proof_systems/ppzksnark/ram_ppzksnark/examples/demo_ram_ppzksnark.cpp.i

depends/libsnark/libsnark/CMakeFiles/demo_ram_ppzksnark.dir/zk_proof_systems/ppzksnark/ram_ppzksnark/examples/demo_ram_ppzksnark.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/demo_ram_ppzksnark.dir/zk_proof_systems/ppzksnark/ram_ppzksnark/examples/demo_ram_ppzksnark.cpp.s"
	cd /home/mbadakhs/Project/zkSNARK/zupply-zkp/build/depends/libsnark/libsnark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/mbadakhs/Project/zkSNARK/zupply-zkp/depends/libsnark/libsnark/zk_proof_systems/ppzksnark/ram_ppzksnark/examples/demo_ram_ppzksnark.cpp -o CMakeFiles/demo_ram_ppzksnark.dir/zk_proof_systems/ppzksnark/ram_ppzksnark/examples/demo_ram_ppzksnark.cpp.s

# Object files for target demo_ram_ppzksnark
demo_ram_ppzksnark_OBJECTS = \
"CMakeFiles/demo_ram_ppzksnark.dir/zk_proof_systems/ppzksnark/ram_ppzksnark/examples/demo_ram_ppzksnark.cpp.o"

# External object files for target demo_ram_ppzksnark
demo_ram_ppzksnark_EXTERNAL_OBJECTS =

depends/libsnark/libsnark/demo_ram_ppzksnark: depends/libsnark/libsnark/CMakeFiles/demo_ram_ppzksnark.dir/zk_proof_systems/ppzksnark/ram_ppzksnark/examples/demo_ram_ppzksnark.cpp.o
depends/libsnark/libsnark/demo_ram_ppzksnark: depends/libsnark/libsnark/CMakeFiles/demo_ram_ppzksnark.dir/build.make
depends/libsnark/libsnark/demo_ram_ppzksnark: depends/libsnark/libsnark/libsnark.a
depends/libsnark/libsnark/demo_ram_ppzksnark: /usr/lib/x86_64-linux-gnu/libboost_program_options.so.1.71.0
depends/libsnark/libsnark/demo_ram_ppzksnark: depends/libsnark/depends/libff/libff/libff.a
depends/libsnark/libsnark/demo_ram_ppzksnark: /usr/lib/x86_64-linux-gnu/libgmp.so
depends/libsnark/libsnark/demo_ram_ppzksnark: /usr/lib/x86_64-linux-gnu/libgmp.so
depends/libsnark/libsnark/demo_ram_ppzksnark: /usr/lib/x86_64-linux-gnu/libgmpxx.so
depends/libsnark/libsnark/demo_ram_ppzksnark: depends/libsnark/depends/libzm.a
depends/libsnark/libsnark/demo_ram_ppzksnark: depends/libsnark/libsnark/CMakeFiles/demo_ram_ppzksnark.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/mbadakhs/Project/zkSNARK/zupply-zkp/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable demo_ram_ppzksnark"
	cd /home/mbadakhs/Project/zkSNARK/zupply-zkp/build/depends/libsnark/libsnark && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/demo_ram_ppzksnark.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
depends/libsnark/libsnark/CMakeFiles/demo_ram_ppzksnark.dir/build: depends/libsnark/libsnark/demo_ram_ppzksnark

.PHONY : depends/libsnark/libsnark/CMakeFiles/demo_ram_ppzksnark.dir/build

depends/libsnark/libsnark/CMakeFiles/demo_ram_ppzksnark.dir/clean:
	cd /home/mbadakhs/Project/zkSNARK/zupply-zkp/build/depends/libsnark/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/demo_ram_ppzksnark.dir/cmake_clean.cmake
.PHONY : depends/libsnark/libsnark/CMakeFiles/demo_ram_ppzksnark.dir/clean

depends/libsnark/libsnark/CMakeFiles/demo_ram_ppzksnark.dir/depend:
	cd /home/mbadakhs/Project/zkSNARK/zupply-zkp/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/mbadakhs/Project/zkSNARK/zupply-zkp /home/mbadakhs/Project/zkSNARK/zupply-zkp/depends/libsnark/libsnark /home/mbadakhs/Project/zkSNARK/zupply-zkp/build /home/mbadakhs/Project/zkSNARK/zupply-zkp/build/depends/libsnark/libsnark /home/mbadakhs/Project/zkSNARK/zupply-zkp/build/depends/libsnark/libsnark/CMakeFiles/demo_ram_ppzksnark.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : depends/libsnark/libsnark/CMakeFiles/demo_ram_ppzksnark.dir/depend

