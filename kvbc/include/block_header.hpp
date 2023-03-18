// Copyright (c) 2023 VMware, Inc. All Rights Reserved.
//
// This product is licensed to you under the Apache 2.0 license (the
// "License").  You may not use this product except in compliance with the
// Apache 2.0 License.
//
// This product may include a number of subcomponents with separate copyright
// notices and license terms. Your use of these subcomponents is subject to the
// terms and conditions of the subcomponent's license, as noted in the LICENSE
// file.
//
#pragma once
#include <vector>
#include <string>
#include "util/serializable.hpp"
#include "crypto/digest.hpp"
#include "kvbc_app_filter/kvbc_key_types.h"

namespace concord::kvbc {

const int64_t kBlockStorageVersion = 1;
using uint256be = std::array<uint8_t, 32>;
using nonce_t = std::array<uint8_t, 8>;

typedef struct BlockHeader {
  uint64_t number;
  uint64_t timestamp;
  uint256be parent_hash;
  uint256be stateroot;
  uint64_t gas_limit;
  uint64_t gas_used;
  std::vector<uint256be> transactions;
  uint256be extra_data;
  uint256be miner;
  nonce_t nonce;

  static const auto kHashSizeInBytes = 32;
  static const std::string blockNumAsKeyToBlockHash(const uint8_t *bytes, size_t length);
  static const std::string blockNumAsKeyToBlockHeader(const uint8_t *bytes, size_t length);
  uint256be hash() const;
  std::string serialize() const;
  static struct BlockHeader deserialize(const std::string &input);
} BlockHeader;

}  // namespace concord::kvbc