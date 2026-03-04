# Copyright (c) 2017-2024 The Bitcoin developers
# Copyright (c) 2025 The Bitcoin Cash II developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

add_library(seeder_common STATIC
    bitcoin.cpp
    db.cpp
    dns.cpp
    util.cpp
)

target_link_libraries(seeder_common
    PRIVATE
        core_interface
        bitcoin_common
        bitcoin_node
)

add_executable(bch2-seeder
    main.cpp
)

target_link_libraries(bch2-seeder
    PRIVATE
        core_interface
        seeder_common
        bitcoin_common
        bitcoin_node
)

if(BUILD_TESTS)
    add_subdirectory(test)
endif()
