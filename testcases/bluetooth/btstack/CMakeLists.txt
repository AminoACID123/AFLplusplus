cmake_minimum_required (VERSION 3.5)

#set(CMAKE_C_COMPILER wllvm)
#set(CMAKE_CXX_COMPILER wllvm++)
set(BTSTACK_ROOT /home/xaz/Documents/lightblue/btstack)

project(BTstack_FUZZ)

include_directories(.)

include_directories(${BTSTACK_ROOT}/3rd-party/micro-ecc)
include_directories(${BTSTACK_ROOT}/3rd-party/bluedroid/decoder/include)
include_directories(${BTSTACK_ROOT}/3rd-party/bluedroid/encoder/include)
include_directories(${BTSTACK_ROOT}/3rd-party/lc3-google/include)
include_directories(${BTSTACK_ROOT}/3rd-party/md5)
include_directories(${BTSTACK_ROOT}/3rd-party/hxcmod-player)
include_directories(${BTSTACK_ROOT}/3rd-party/hxcmod-player/mod)
include_directories(${BTSTACK_ROOT}/3rd-party/lwip/core/src/include)
include_directories(${BTSTACK_ROOT}/3rd-party/lwip/dhcp-server)
include_directories(${BTSTACK_ROOT}/3rd-party/rijndael)
include_directories(${BTSTACK_ROOT}/3rd-party/yxml)
include_directories(${BTSTACK_ROOT}/3rd-party/tinydir)
include_directories(${BTSTACK_ROOT}/src)
include_directories(${BTSTACK_ROOT}/chipset/bcm)
include_directories(${BTSTACK_ROOT}/chipset/csr)
include_directories(${BTSTACK_ROOT}/chipset/cc256x)
include_directories(${BTSTACK_ROOT}/chipset/em9301)
include_directories(${BTSTACK_ROOT}/chipset/realtek)
include_directories(${BTSTACK_ROOT}/chipset/tc3566x)
include_directories(${BTSTACK_ROOT}/chipset/stlc2500d)
include_directories(${BTSTACK_ROOT}/chipset/zephyr)
include_directories(${BTSTACK_ROOT}/platform/embedded)
include_directories(${BTSTACK_ROOT}/platform/lwip)
include_directories(${BTSTACK_ROOT}/platform/lwip/port)
include_directories(${BTSTACK_ROOT}/platform/posix)

file(GLOB SOURCES_SRC       "${BTSTACK_ROOT}/src/*.c" "${BTSTACK_ROOT}/example/sco_demo_util.c")
file(GLOB SOURCES_BLE       "${BTSTACK_ROOT}/src/ble/*.c")
file(GLOB SOURCES_BLUEDROID "${BTSTACK_ROOT}/3rd-party/bluedroid/encoder/srce/*.c" "${BTSTACK_ROOT}/3rd-party/bluedroid/decoder/srce/*.c")
file(GLOB SOURCES_CLASSIC   "${BTSTACK_ROOT}/src/classic/*.c")
file(GLOB SOURCES_MESH      "${BTSTACK_ROOT}/src/mesh/*.c")
file(GLOB SOURCES_GATT      "${BTSTACK_ROOT}/src/ble/gatt-service/*.c")
file(GLOB SOURCES_UECC      "${BTSTACK_ROOT}/3rd-party/micro-ecc/uECC.c")
file(GLOB SOURCES_HXCMOD    "${BTSTACK_ROOT}/3rd-party/hxcmod-player/*.c"  "${BTSTACK_ROOT}/3rd-party/hxcmod-player/mods/*.c")
file(GLOB SOURCES_MD5       "${BTSTACK_ROOT}/3rd-party/md5/md5.c")
file(GLOB SOURCES_RIJNDAEL  "${BTSTACK_ROOT}/3rd-party/rijndael/rijndael.c")
file(GLOB SOURCES_YXML      "${BTSTACK_ROOT}/3rd-party/yxml/yxml.c")
file(GLOB SOURCES_POSIX     "${BTSTACK_ROOT}/platform/posix/*.c")
file(GLOB SOURCES_BCM       "${BTSTACK_ROOT}/chipset/bcm/*.c")
file(GLOB SOURCES_CSR       "${BTSTACK_ROOT}/chipset/csr/*.c")
file(GLOB SOURCES_EM9301    "${BTSTACK_ROOT}/chipset/em9301/*.c")
file(GLOB SOURCES_STLC2500D "${BTSTACK_ROOT}/chipset/stlc2500d/*.c")
file(GLOB SOURCES_TC2566X   "${BTSTACK_ROOT}/chipset/tc3566x/*.c")
file(GLOB SOURCES_REALTEK   "${BTSTACK_ROOT}/chipset/realtek/*.c")
file(GLOB SOURCES_ZEPHYR    "${BTSTACK_ROOT}/chipset/zephyr/*.c")
file(GLOB SOURCES_LC3_GOOGLE "${BTSTACK_ROOT}/3rd-party/lc3-google/src/*.c")


set(LWIP_CORE_SRC
		${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/def.c
		${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/inet_chksum.c
		${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/init.c
		${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/ip.c
		${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/mem.c
		${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/memp.c
		${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/netif.c
		${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/pbuf.c
		${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/tcp.c
		${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/tcp_in.c
		${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/tcp_out.c
		${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/timeouts.c
		${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/udp.c
		)
set (LWIP_IPV4_SRC
		${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/ipv4/acd.c
		${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/ipv4/dhcp.c
		${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/ipv4/etharp.c
		${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/ipv4/icmp.c
		${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/ipv4/ip4.c
		${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/ipv4/ip4_addr.c
		${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/ipv4/ip4_frag.c
		)
set (LWIP_NETIF_SRC
		${BTSTACK_ROOT}/3rd-party/lwip/core/src/netif/ethernet.c
		)
set (LWIP_HTTPD
		${BTSTACK_ROOT}/3rd-party/lwip/core/src/apps/http/altcp_proxyconnect.c
		${BTSTACK_ROOT}/3rd-party/lwip/core/src/apps/http/fs.c
		${BTSTACK_ROOT}/3rd-party/lwip/core/src/apps/http/httpd.c
		)
set (LWIP_DHCPD
		${BTSTACK_ROOT}/3rd-party/lwip/dhcp-server/dhserver.c
		)
set (LWIP_PORT
		${BTSTACK_ROOT}/platform/lwip/port/sys_arch.c
		${BTSTACK_ROOT}//platform/lwip/bnep_lwip.c
		)
set (SOURCES_LWIP ${LWIP_CORE_SRC} ${LWIP_IPV4_SRC} ${LWIP_NETIF_SRC} ${LWIP_HTTPD} ${LWIP_DHCPD} ${LWIP_PORT})

file(GLOB SOURCES_BLE_OFF "${BTSTACK_ROOT}/src/ble/le_device_db_memory.c")
list(REMOVE_ITEM SOURCES_BLE   ${SOURCES_BLE_OFF})

file(GLOB SOURCES_POSIX_OFF "${BTSTACK_ROOT}/platform/posix/le_device_db_fs.c")
list(REMOVE_ITEM SOURCES_POSIX   ${SOURCES_POSIX_OFF})

set(SOURCES
		${SOURCES_BLE}
		${SOURCES_BCM}
		${SOURCES_BLUEDROID}
		${SOURCES_CLASSIC}
		${SOURCES_CSR}
		${SOURCES_EM9301}
		${SOURCES_GATT}
		${SOURCES_HXCMOD}
		${SOURCES_HXCMOD}
		${SOURCES_LIBUSB}
		${SOURCES_MD5}
		${SOURCES_MESH}
		${SOURCES_PORT}
		${SOURCES_REALTEK}
		${SOURCES_RIJNDAEL}
		${SOURCES_SRC}
		${SOURCES_CSR}
		${SOURCES_STLC2500D}
		${SOURCES_TC2566X}
		${SOURCES_UECC}
		${SOURCES_POSIX}
		${SOURCES_YXML}
		${SOURCES_ZEPHYR}
)
list(SORT SOURCES)

add_compile_options( -g -O0 )
add_link_options(-Wl,--whole-archive)

# add_link_options(       -fsanitize=fuzzer,address -fprofile-instr-generate -fcoverage-mapping)

# create static lib
add_library(btstack STATIC ${SOURCES})


message(STATUS ${CMAKE_C_COMPILER})
if(${CMAKE_C_COMPILER} STREQUAL "/usr/local/bin/afl-clang-lto")
       add_executable(bt main.c hci_transport_fuzz.c run_loop_fuzz.c execute.c harness.c)
       add_link_options(-Wl,--whole-archive)
       target_link_libraries( bt btstack )
endif()