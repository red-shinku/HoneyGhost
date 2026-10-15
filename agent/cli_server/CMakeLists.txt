set(CMAKE_CXX_STANDARD 20)

set(HNG_CLI_PROTO_DIR ${CMAKE_BINARY_DIR}/generated/cli_service)
file(MAKE_DIRECTORY ${HNG_CLI_PROTO_DIR})
userver_add_grpc_library(hng_cli_proto
    PROTOS proto/cli_service.proto
    SOURCE_PATH ${HNG_SOURCE_DIR}
    OUTPUT_PATH ${HNG_CLI_PROTO_DIR}
    INCLUDE_DIRECTORIES ${HNG_SOURCE_DIR}/proto
)

target_link_libraries(hng_cli_proto PUBLIC hng_event_data)

add_library(hng_cli_server STATIC
    src/cli_server.cc
    src/cli_context_query_service.cc
    src/cli_role_query_service.cc
    src/query_handlers.cc
)
target_include_directories(hng_cli_server PUBLIC
    ${HNG_SOURCE_DIR}
)

target_link_libraries(hng_cli_server
    PUBLIC userver::core
            userver::grpc
            hng_cli_proto
            hng_event_data
            hng_control_plane
            hng_runtime_engine
)
target_compile_features(hng_cli_server PUBLIC cxx_std_20)
