# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.19

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


# Command-line exit_flag to silence nested $(MAKE).
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
CMAKE_COMMAND = /cygdrive/c/Users/Xiaomi/AppData/Local/JetBrains/CLion2021.1/cygwin_cmake/bin/cmake.exe

# The command to remove a file.
RM = /cygdrive/c/Users/Xiaomi/AppData/Local/JetBrains/CLion2021.1/cygwin_cmake/bin/cmake.exe -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /cygdrive/c/Users/Xiaomi/CLionProjects/network-final

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /cygdrive/c/Users/Xiaomi/CLionProjects/network-final/cmake-build-release

# Include any dependencies generated for this target.
include CMakeFiles/Client.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/Client.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/Client.dir/flags.make

CMakeFiles/Client.dir/client.c.o: CMakeFiles/Client.dir/flags.make
CMakeFiles/Client.dir/client.c.o: ../client.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/cygdrive/c/Users/Xiaomi/CLionProjects/network-final/cmake-build-release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/Client.dir/client.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/Client.dir/client.c.o -c /cygdrive/c/Users/Xiaomi/CLionProjects/network-final/client.c

CMakeFiles/Client.dir/client.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/Client.dir/client.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /cygdrive/c/Users/Xiaomi/CLionProjects/network-final/client.c > CMakeFiles/Client.dir/client.c.i

CMakeFiles/Client.dir/client.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/Client.dir/client.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /cygdrive/c/Users/Xiaomi/CLionProjects/network-final/client.c -o CMakeFiles/Client.dir/client.c.s

CMakeFiles/Client.dir/hashmap.c.o: CMakeFiles/Client.dir/flags.make
CMakeFiles/Client.dir/hashmap.c.o: ../hashmap.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/cygdrive/c/Users/Xiaomi/CLionProjects/network-final/cmake-build-release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/Client.dir/hashmap.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/Client.dir/hashmap.c.o -c /cygdrive/c/Users/Xiaomi/CLionProjects/network-final/hashmap.c

CMakeFiles/Client.dir/hashmap.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/Client.dir/hashmap.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /cygdrive/c/Users/Xiaomi/CLionProjects/network-final/hashmap.c > CMakeFiles/Client.dir/hashmap.c.i

CMakeFiles/Client.dir/hashmap.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/Client.dir/hashmap.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /cygdrive/c/Users/Xiaomi/CLionProjects/network-final/hashmap.c -o CMakeFiles/Client.dir/hashmap.c.s

# Object files for target Client
Client_OBJECTS = \
"CMakeFiles/Client.dir/client.c.o" \
"CMakeFiles/Client.dir/hashmap.c.o"

# External object files for target Client
Client_EXTERNAL_OBJECTS =

Client.exe: CMakeFiles/Client.dir/client.c.o
Client.exe: CMakeFiles/Client.dir/hashmap.c.o
Client.exe: CMakeFiles/Client.dir/build.make
Client.exe: CMakeFiles/Client.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/cygdrive/c/Users/Xiaomi/CLionProjects/network-final/cmake-build-release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable Client.exe"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/Client.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/Client.dir/build: Client.exe

.PHONY : CMakeFiles/Client.dir/build

CMakeFiles/Client.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/Client.dir/cmake_clean.cmake
.PHONY : CMakeFiles/Client.dir/clean

CMakeFiles/Client.dir/depend:
	cd /cygdrive/c/Users/Xiaomi/CLionProjects/network-final/cmake-build-release && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /cygdrive/c/Users/Xiaomi/CLionProjects/network-final /cygdrive/c/Users/Xiaomi/CLionProjects/network-final /cygdrive/c/Users/Xiaomi/CLionProjects/network-final/cmake-build-release /cygdrive/c/Users/Xiaomi/CLionProjects/network-final/cmake-build-release /cygdrive/c/Users/Xiaomi/CLionProjects/network-final/cmake-build-release/CMakeFiles/Client.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/Client.dir/depend

