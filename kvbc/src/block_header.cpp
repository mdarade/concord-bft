// Concord
//
// Copyright (c) 2023 VMware, Inc. All Rights Reserved.
//
// This product is licensed to you under the Apache 2.0 license (the "License").
// You may not use this product except in compliance with the Apache 2.0
// License.
//
// This product may include a number of subcomponents with separate copyright
// notices and license terms. Your use of these subcomponents is subject to the
// terms and conditions of the subcomponent's license, as noted in the
// LICENSE file.

#include <string.h>

#include "block_header.hpp"
#include "log/logger.hpp"
#include "kvbc_key_types.hpp"
#include "categorized_kvbc_msgs.cmf.hpp"

using concord::kvbc::categorization::BlockHeaderData;
using namespace concord::serialize;
using concord::kvbc::keyTypes::kKvbKeyBlockHeaderHash;

namespace concord::kvbc {

std::string BlockHeader::serialize() const {
  BlockHeaderData out;

  out.version = kBlockStorageVersion;
  out.number = number;
  std::copy(parent_hash.begin(), parent_hash.end(), out.parent_hash.begin());
  // TODO - reserve once and then use index?
  for (int i = 0; i < transactions.size(); i++) {
    uint256be txn;
    std::copy(transactions[i].begin(), transactions[i].end(), txn.begin());
    out.transactions.push_back(txn);
  }
  out.timestamp = timestamp;
  out.gas_limit = gas_limit;
  out.gas_used = gas_used;
  std::copy(stateroot.begin(), stateroot.end(), out.stateroot.begin());
  std::copy(extra_data.begin(), extra_data.end(), out.extra_data.begin());
  std::copy(miner.begin(), miner.end(), out.miner.begin());
  std::copy(nonce.begin(), nonce.end(), out.nonce.begin());

  std::string serialized_buffer;
  categorization::serialize(serialized_buffer, out);
  ConcordAssert(serialized_buffer.size() > 0);
  return serialized_buffer;
}

struct BlockHeader BlockHeader::deserialize(const std::string &input) {
  BlockHeaderData inblk;
  categorization::deserialize(input, inblk);
  if (inblk.version != kBlockStorageVersion) {
    LOG_ERROR(V4_BLOCK_LOG, "Unknown block storage version " << inblk.version);
    throw std::runtime_error("Unkown block storage version");
  }
  BlockHeader outblk;
  outblk.number = inblk.number;
  std::copy(inblk.parent_hash.begin(), inblk.parent_hash.end(), outblk.parent_hash.begin());
  for (int i = 0; i < inblk.transactions.size(); i++) {
    uint256be txn;
    std::copy(inblk.transactions[i].begin(), inblk.transactions[i].end(), txn.begin());
    outblk.transactions.push_back(txn);
  }
  outblk.timestamp = inblk.timestamp;
  outblk.gas_limit = inblk.gas_limit;
  outblk.gas_used = inblk.gas_used;
  std::copy(inblk.stateroot.begin(), inblk.stateroot.end(), outblk.stateroot.begin());
  std::copy(inblk.extra_data.begin(), inblk.extra_data.end(), outblk.extra_data.begin());
  std::copy(inblk.miner.begin(), inblk.miner.end(), outblk.miner.begin());
  std::copy(inblk.nonce.begin(), inblk.nonce.end(), outblk.nonce.begin());
  return outblk;
}

const std::string BlockHeader::blockNumAsKeyToBlockHash(const uint8_t *bytes, size_t length) {
  std::string ret;
  ret.push_back((char)kKvbKeyBlockHeaderHash);
  ret.append(reinterpret_cast<const char *>(bytes), length);
  return ret;
}

const std::string BlockHeader::blockNumAsKeyToBlockHeader(const uint8_t *bytes, size_t length) {
  std::string ret;
  ret.push_back((char)kKvbKeyEthBlockHash);
  ret.append(reinterpret_cast<const char *>(bytes), length);
  return ret;
}

uint256be BlockHeader::hash() const {
  static_assert(sizeof(crypto::BlockDigest) == sizeof(uint256be), "hash size should be same");

  // TODO - We can't simply call serialize() of this class as we don't want block version to be part of serialized
  // header ?? auto serialized_header = serialize();

  std::ostringstream os;
  Serializable::serialize(os, number);
  Serializable::serialize(os, timestamp);
  Serializable::serialize(os, reinterpret_cast<const char *>(parent_hash.data()), sizeof(parent_hash));
  Serializable::serialize(os, reinterpret_cast<const char *>(stateroot.begin()), sizeof(stateroot));
  Serializable::serialize(os, gas_limit);
  Serializable::serialize(os, gas_used);
  for (auto txn : transactions) {
    Serializable::serialize(os, reinterpret_cast<const char *>(txn.begin()), sizeof(txn));
  }
  Serializable::serialize(os, reinterpret_cast<const char *>(extra_data.begin()), sizeof(extra_data));
  Serializable::serialize(os, reinterpret_cast<const char *>(miner.begin()), sizeof(miner));
  Serializable::serialize(os, reinterpret_cast<const char *>(nonce.begin()), sizeof(nonce));
  auto serialized_header = os.str();

  crypto::DigestGenerator digest_generator;
  uint256be hash;
  digest_generator.update(reinterpret_cast<const char *>(serialized_header.c_str()), serialized_header.size());
  digest_generator.writeDigest(reinterpret_cast<char *>(hash.data()));
  return hash;
}

}  // namespace concord::kvbc