cmake_minimum_required(VERSION 3.22.1)
project(spdecode LANGUAGES CXX)
add_library(spdecode SHARED spdecode_transport.cpp)
# The public HTTPS API origin is compiled into libspdecode.so, not passed by UI.
target_compile_definitions(spdecode PRIVATE "SPDECODE_CLOUD_ORIGIN=\"${SPDECODE_CLOUD_ORIGIN}\"")
set_target_properties(spdecode PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
target_compile_options(spdecode PRIVATE -Wall -Wextra -Werror -fvisibility=hidden -fstack-protector-strong)
target_link_options(spdecode PRIVATE -Wl,-z,relro,-z,now)
