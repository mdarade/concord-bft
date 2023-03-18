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
// terms and conditions of the subcomponent's license, as noted in the LICENSE
// file.

#include "kvbc_adapter/v4blockchain/blocks_adder_adapter.hpp"
#include "kvbc_app_filter/kvbc_key_types.h"
#include "categorization/db_categories.h"
#include "bftengine/ReplicaConfig.hpp"

using bftEngine::ReplicaConfig;

namespace concord::kvbc::adapter::v4blockchain {

void BlocksAdderAdapter::getParentHeaderHash_(const BlockId number, uint256be &parent_hash) {
  ConcordAssert(number > 0);
  auto parent_block_number = number - 1;
  auto block_num_as_key_to_block_hash =
      BlockHeader::blockNumAsKeyToBlockHash((uint8_t *)&(parent_block_number), sizeof(number));
  LOG_DEBUG(
      GL,
      KVLOG(parent_block_number,
            concordUtils::bufferToHex(block_num_as_key_to_block_hash.c_str(), block_num_as_key_to_block_hash.size())));
  auto opt_val = kvbc_->getLatest(kvbc::categorization::kExecutionPrivateCategory, block_num_as_key_to_block_hash);
  if (opt_val) {
    auto val = std::get<kvbc::categorization::VersionedValue>(*opt_val);
    std::copy(val.data.begin(), val.data.end(), parent_hash.begin());
  }
}

BlockId BlocksAdderAdapter::add(concord::kvbc::categorization::Updates &&updates) {
  if (bftEngine::ReplicaConfig::instance().ethDeployment == true) {
    auto cat_itr = updates.categoryUpdates().kv.find(kvbc::categorization::kExecutionPrivateCategory);

    BlockHeader header{0};
    std::string serialized_header;

    // block N in app state == block N + 1 in KVBC
    auto last_reachable_block_num = kvbc_->getLastReachableBlockId();
    BlockId to_be_written_block_num = last_reachable_block_num;
    auto to_be_written_block_header_key =
        BlockHeader::blockNumAsKeyToBlockHeader((uint8_t *)&to_be_written_block_num, sizeof(to_be_written_block_num));
    LOG_DEBUG(GL,
              "key size " << to_be_written_block_header_key.size() << " key hash "
                          << std::hash<std::string>{}(to_be_written_block_header_key) << " key "
                          << concordUtils::bufferToHex(to_be_written_block_header_key.c_str(),
                                                       to_be_written_block_header_key.size()));

    if (cat_itr != updates.categoryUpdates().kv.cend()) {
      const auto &kvs = std::get<kvbc::categorization::VersionedInput>(cat_itr->second).kv;
      auto key_itr = kvs.find(to_be_written_block_header_key);
      if (key_itr != kvs.cend()) {
        // Eth block; just compute hash of already written header in updates
        serialized_header = key_itr->second.data;
        header = BlockHeader::deserialize(serialized_header);
      }
    }

    // could not find existing blockheader
    if (serialized_header.empty()) {
      // Reconfig block; !Eth block; construct BlockHeader
      if (last_reachable_block_num) {
        // we are sure genesis is already written
        header.number = to_be_written_block_num;
        getParentHeaderHash_(last_reachable_block_num, header.parent_hash);
        ConcordAssertEQ(header.parent_hash.empty(), false);
      }

      // add serialized block header into updates
      serialized_header = header.serialize();
      updates.addCategoryIfNotExisting<kvbc::categorization::VersionedInput>(
          concord::kvbc::categorization::kExecutionPrivateCategory);
      updates.appendKeyValue<kvbc::categorization::VersionedUpdates>(
          concord::kvbc::categorization::kExecutionPrivateCategory,
          std::move(to_be_written_block_header_key),
          kvbc::categorization::VersionedUpdates::Value{serialized_header, true});
      LOG_DEBUG(
          GL,
          "Eth block number " << to_be_written_block_num << " header size " << serialized_header.size()
                              << " parent hash "
                              << concordUtils::bufferToHex(header.parent_hash.begin(), header.parent_hash.size()));
    }

    // std::array<uint8_t, 32> header_hash{0};
    // add header hash into updates
    auto header_hash = header.hash();
    auto block_num_as_key_to_block_hash =
        BlockHeader::blockNumAsKeyToBlockHash((uint8_t *)&to_be_written_block_num, sizeof(to_be_written_block_num));
    updates.appendKeyValue<kvbc::categorization::VersionedUpdates>(
        concord::kvbc::categorization::kExecutionPrivateCategory,
        std::move(block_num_as_key_to_block_hash),
        kvbc::categorization::VersionedUpdates::Value{reinterpret_cast<char *>(header_hash.begin()), true});
    LOG_DEBUG(GL,
              "Eth Block number " << to_be_written_block_num << " and its header hash "
                                  << concordUtils::bufferToHex(header_hash.begin(), header_hash.size()));
  }
  return kvbc_->add(std::move(updates));
}

}  // namespace concord::kvbc::adapter::v4blockchain