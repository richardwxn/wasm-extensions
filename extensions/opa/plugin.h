/* Copyright 2019 Istio Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "absl/container/flat_hash_map.h"

#ifndef NULL_PLUGIN

#include <assert.h>
#define ASSERT(_X) assert(_X)

#include "proxy_wasm_intrinsics.h"

#else

#include "include/proxy-wasm/null_plugin.h"

namespace proxy_wasm {
namespace null_plugin {
namespace OPA {
namespace Plugin {

#endif

// PluginRootContext is the root context for all streams processed by the
// thread. It has the same lifetime as the worker thread and acts as target for
// interactions that outlives individual stream, e.g. timer, async calls.
class PluginRootContext : public RootContext {
 public:
  PluginRootContext(uint32_t id, std::string_view root_id)
      : RootContext(id, root_id) {}
  ~PluginRootContext() = default;

  bool onConfigure(size_t) override;
  bool configure(size_t);

  bool initialized() const { return initialized_; };

  // Validate OPA plugin configuration, which will cause an listener update to
  // be rejected.
  bool validateConfiguration(size_t /* configuration_size */) override;

  const std::string &opaServiceHost() { return config_.opa_service_host(); }
  const std::string &opaClusterName() { return config_.opa_cluster_name(); }

  bool checkCache(const OPAPayload &payload,
                  uint64_t &hash, bool &allowed) {
    bool hit = cache_.check(payload, hash, allowed, getCurrentTimeNanoseconds());
    incrementMetric((hit ? cache_hits_ : cache_misses_), 1);
    return hit;
  }
  void addCache(const uint64_t hash, bool result) {
    cache_.add(hash, result, getCurrentTimeNanoseconds());
  }

 private:
  ResultCache cache_;

  uint64_t cache_valid_ruation;

  uint32_t cache_hits_;
  uint32_t cache_misses_;

  bool initialized_ = false;
};

// Per-stream context.
class PluginContext : public Context {
 public:
  explicit PluginContext(uint32_t id, RootContext* root) : Context(id, root) {}

  FilterHeadersStatus onRequestHeaders(uint32_t, bool);

 private:
  inline PluginRootContext* rootContext() {
    return dynamic_cast<PluginRootContext*>(this->root());
  };
};


struct OPAPayload {
  std::string source_principal;
  std::string destination_service;
  std::string request_operation;
  std::string request_url_path;
};

struct OPAResponse {
  bool result;
}


#ifdef NULL_PLUGIN
}  // namespace Plugin
}  // namespace OPA
}  // namespace null_plugin
}  // namespace proxy_wasm
#endif
