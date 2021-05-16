cmake_minimum_required(VERSION 3.19)
project(nwproj C)

set(CMAKE_C_STANDARD 11)

set(SOURCE_FILES
        client.c
        server.c)

include_directories(.)

add_executable(Client client.c)
add_executable(Server server.c)
