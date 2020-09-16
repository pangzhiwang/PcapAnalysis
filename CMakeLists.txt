cmake_minimum_required(VERSION 3.2)
include_directories(./)
file(GLOB srcs ./*.c ./protocol/*.c ./util/*.c)
add_executable(dpi ./samples/main.c ${srcs})
target_link_libraries(dpi pcap)
#测试链表的测试程序
add_executable(test_list ./samples/test_list.c ${srcs})
target_link_libraries(test_list pcap)
