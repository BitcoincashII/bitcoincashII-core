// Copyright (c) 2017-2024 The Bitcoin developers
// Copyright (c) 2025 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOINII_SEEDER_UTIL_H
#define BITCOINII_SEEDER_UTIL_H

#include <cstdint>

namespace seeder {

// Sleeps for the requested number of milliseconds. Returns true on success or false if short sleep due to app shutdown.
extern bool SleepAndPollShutdownFlag(int64_t nMilliSec);

// Returns true if app shutdown was requested, false otherwise.
extern bool ShutdownRequested();

// Do not call this from a signal handler. Sets the internal "shutdown requested" flag to true, and also signals an
// internal condition variable to wake sleepers.
extern void RequestShutdown();

} // namespace seeder

#endif // BITCOINII_SEEDER_UTIL_H
