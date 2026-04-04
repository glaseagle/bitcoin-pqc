// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Policy (standardness) interface for PQC output types.

#ifndef BITCOIN_POLICY_POLICY_PQC_H
#define BITCOIN_POLICY_POLICY_PQC_H

#include <cstdint>
#include <span>
#include <string>
#include <vector>

bool IsStandardPQCOutput(std::span<const uint8_t> spk, std::string& reason);

bool IsStandardPQCInput(
    uint8_t                                  type_byte,
    const std::vector<std::vector<uint8_t>>& witness,
    std::span<const uint8_t>                 scriptsig,
    std::string&                             reason);

size_t GetPQCInputWeight(uint8_t type_byte);
size_t GetPQCOutputWeight();

#endif // BITCOIN_POLICY_POLICY_PQC_H
