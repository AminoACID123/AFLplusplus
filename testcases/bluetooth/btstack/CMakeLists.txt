cmake_minimum_required (VERSION 3.5)

set(CMAKE_C_COMPILER afl-clang-lto)
set(CMAKE_CXX_COMPILER afl-clang-lto++)
set(PROJ_ROOT /home/xaz/Documents/lightblue/btstack)

project(BTstack)

include_directories(${PROJ_ROOT}/3rd-party/lc3-google/include)
include_directories(${PROJ_ROOT}/3rd-party/micro-ecc)
include_directories(${PROJ_ROOT}/3rd-party/bluedroid/decoder/include)
include_directories(${PROJ_ROOT}/3rd-party/bluedroid/encoder/include)
include_directories(${PROJ_ROOT}/3rd-party/md5)
include_directories(${PROJ_ROOT}/3rd-party/hxcmod-player)
include_directories(${PROJ_ROOT}/3rd-party/hxcmod-player/mod)
include_directories(${PROJ_ROOT}/3rd-party/lwip/core/src/include)
include_directories(${PROJ_ROOT}/3rd-party/lwip/dhcp-server)
include_directories(${PROJ_ROOT}/3rd-party/rijndael)
include_directories(${PROJ_ROOT}/3rd-party/yxml)
include_directories(${PROJ_ROOT}/3rd-party/tinydir)
include_directories(${PROJ_ROOT}/src)
include_directories(${PROJ_ROOT}/platform/posix)
include_directories(${PROJ_ROOT}/platform/embedded)
include_directories(${PROJ_ROOT}/platform/lwip)
include_directories(${PROJ_ROOT}/platform/lwip/port)
include_directories(.)

file(GLOB SOURCES_SRC       ${PROJ_ROOT}/src/*.c ${PROJ_ROOT}/example/sco_demo_util.c)
file(GLOB SOURCES_BLE       ${PROJ_ROOT}/src/ble/*.c)
file(GLOB SOURCES_GATT      ${PROJ_ROOT}/src/ble/gatt-service/*.c)
file(GLOB SOURCES_CLASSIC   ${PROJ_ROOT}/src/classic/*.c)
file(GLOB SOURCES_MESH      ${PROJ_ROOT}/src/mesh/*.c)
file(GLOB SOURCES_BLUEDROID ${PROJ_ROOT}/3rd-party/bluedroid/encoder/srce/*.c ${PROJ_ROOT}/3rd-party/bluedroid/decoder/srce/*.c)
file(GLOB SOURCES_MD5       ${PROJ_ROOT}/3rd-party/md5/md5.c)
file(GLOB SOURCES_UECC      ${PROJ_ROOT}/3rd-party/micro-ecc/uECC.c)
file(GLOB SOURCES_YXML      ${PROJ_ROOT}/3rd-party/yxml/yxml.c)
file(GLOB SOURCES_HXCMOD    ${PROJ_ROOT}/3rd-party/hxcmod-player/*.c  ${PROJ_ROOT}/3rd-party/hxcmod-player/mods/*.c)
file(GLOB SOURCES_RIJNDAEL  ${PROJ_ROOT}/3rd-party/rijndael/rijndael.c)
file(GLOB SOURCES_POSIX     ${PROJ_ROOT}/platform/posix/*.c)
file(GLOB SOURCES_LIBUSB    ${PROJ_ROOT}/port/libusb/*.c ${PROJ_ROOT}/platform/libusb/*.c)

set(LWIP_CORE_SRC
        ${PROJ_ROOT}/3rd-party/lwip/core/src/core/def.c
        ${PROJ_ROOT}/3rd-party/lwip/core/src/core/inet_chksum.c
        ${PROJ_ROOT}/3rd-party/lwip/core/src/core/init.c
        ${PROJ_ROOT}/3rd-party/lwip/core/src/core/ip.c
        ${PROJ_ROOT}/3rd-party/lwip/core/src/core/mem.c
        ${PROJ_ROOT}/3rd-party/lwip/core/src/core/memp.c
        ${PROJ_ROOT}/3rd-party/lwip/core/src/core/netif.c
        ${PROJ_ROOT}/3rd-party/lwip/core/src/core/pbuf.c
        ${PROJ_ROOT}/3rd-party/lwip/core/src/core/tcp.c
        ${PROJ_ROOT}/3rd-party/lwip/core/src/core/tcp_in.c
        ${PROJ_ROOT}/3rd-party/lwip/core/src/core/tcp_out.c
        ${PROJ_ROOT}/3rd-party/lwip/core/src/core/timeouts.c
        ${PROJ_ROOT}/3rd-party/lwip/core/src/core/udp.c
        )
set (LWIP_IPV4_SRC
        ${PROJ_ROOT}/3rd-party/lwip/core/src/core/ipv4/acd.c
        ${PROJ_ROOT}/3rd-party/lwip/core/src/core/ipv4/dhcp.c
        ${PROJ_ROOT}/3rd-party/lwip/core/src/core/ipv4/etharp.c
        ${PROJ_ROOT}/3rd-party/lwip/core/src/core/ipv4/icmp.c
        ${PROJ_ROOT}/3rd-party/lwip/core/src/core/ipv4/ip4.c
        ${PROJ_ROOT}/3rd-party/lwip/core/src/core/ipv4/ip4_addr.c
        ${PROJ_ROOT}/3rd-party/lwip/core/src/core/ipv4/ip4_frag.c
        )
set (LWIP_NETIF_SRC
        ${PROJ_ROOT}/3rd-party/lwip/core/src/netif/ethernet.c
        )
set (LWIP_HTTPD
        ${PROJ_ROOT}/3rd-party/lwip/core/src/apps/http/altcp_proxyconnect.c
        ${PROJ_ROOT}/3rd-party/lwip/core/src/apps/http/fs.c
        ${PROJ_ROOT}/3rd-party/lwip/core/src/apps/http/httpd.c
        )
set (LWIP_DHCPD
       ${PROJ_ROOT}/3rd-party/lwip/dhcp-server/dhserver.c
        )
set (LWIP_PORT
        ${PROJ_ROOT}/platform/lwip/port/sys_arch.c
        ${PROJ_ROOT}/platform/lwip/bnep_lwip.c
        )

set (SOURCES_LWIP ${LWIP_CORE_SRC} ${LWIP_IPV4_SRC} ${LWIP_NETIF_SRC} ${LWIP_HTTPD} ${LWIP_DHCPD} ${LWIP_PORT})

file(GLOB SOURCES_BLE_OFF ${PROJ_ROOT}/src/ble/le_device_db_memory.c)
list(REMOVE_ITEM SOURCES_BLE   ${SOURCES_BLE_OFF})

file(GLOB SOURCES_POSIX_OFF ${PROJ_ROOT}/platform/posix/le_device_db_fs.c)
list(REMOVE_ITEM SOURCES_POSIX ${SOURCES_POSIX_OFF})

set(SOURCES
        ${SOURCES_MD5}
        ${SOURCES_YXML}
        ${SOURCES_BLUEDROID}
        ${SOURCES_POSIX}
        ${SOURCES_RIJNDAEL}
        ${SOURCES_SRC}
        ${SOURCES_BLE}
        ${SOURCES_GATT}
        ${SOURCES_MESH}
        ${SOURCES_CLASSIC}
        ${SOURCES_UECC}
        ${SOURCES_HXCMOD}
        )
list(SORT SOURCES)

add_compile_options( -g)
# add_link_options(       -fsanitize=fuzzer,address -fprofile-instr-generate -fcoverage-mapping)

# create static lib
add_library(btstack STATIC ${SOURCES})

add_executable(bt main.c hci_transport_fuzz.c run_loop_fuzz.c port.c harness.c)

target_link_libraries( bt btstack )
