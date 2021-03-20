/* Copyright 2021 Istio Authors. All Rights Reserved.
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

#include "extensions/opa/plugin.h"

#include "absl/strings/str_cat.h"
#include "extensions/common/wasm/json_util.h"

using ::nlohmann::json;
using ::Wasm::Common::JsonArrayIterate;
using ::Wasm::Common::JsonGetField;
using ::Wasm::Common::JsonObjectIterate;
using ::Wasm::Common::JsonValueAs;

#ifndef NULL_PLUGIN

#include "proxy_wasm_intrinsics.h"

#else
#include "include/proxy-wasm/null_plugin.h"

namespace proxy_wasm {
namespace null_plugin {
namespace OPA {
namespace Plugin {

PROXY_WASM_NULL_PLUGIN_REGISTRY;

#endif

using google::protobuf::util::JsonParseOptions;
using google::protobuf::util::Status;

#include "contrib/proxy_expr.h"

static RegisterContextFactory register_Opa(CONTEXT_FACTORY(PluginContext), ROOT_FACTORY(PluginRootContext));

bool PluginRootContext::onConfigure(size_t size) {
  initialized_ = configure(size);
  cache_.setDuration
  return true;
}

bool PluginRootContext::configure(size_t configuration_size) {
  auto configuration_data = getBufferBytes(WasmBufferType::PluginConfiguration,
                                           0, configuration_size);
  auto result = ::Wasm::Common::JsonParse(configuration_data->view());
  if (!result.has_value()) {
    LOG_WARN(absl::StrCat("cannot parse plugin configuration JSON string: ",
                          configuration_data->view()));
    return false;
  }
  // j is a JsonObject holds configuration data
  auto j = result.value();

  // Parse and get opa service host.
  auto it = j.find("opa_service_host");
  if (it != j.end()) {
    auto opa_host_val = JsonValueAs<std::string>(it.value());
    if (opa_host_val.second != Wasm::Common::JsonParserResultDetail::OK) {
      LOG_WARN(absl::StrCat(
          "cannot parse opa service host in plugin configuration JSON string: ",
          configuration_data->view()));
      return false;
    }
    opa_host_ = opa_host_val.first.value();
  } else {
    LOG_WARN(
        absl::StrCat("opa service host must be provided in plugin "
                     "configuration JSON string: ",
                     configuration_data->view()));
    return false;
  }

  it = j.find("opa_cluster_name");
  if (it != j.end()) {
    auto opa_cluster_val = JsonValueAs<std::string>(it.value());
    if (opa_cluster_val.second != Wasm::Common::JsonParserResultDetail::OK) {
      LOG_WARN(absl::StrCat(
          "cannot parse opa cluster name in plugin configuration JSON string: ",
          configuration_data->view()));
      return false;
    }
    opa_cluster_ = opa_cluster_val.first.value();
  } else {
    LOG_WARN(
        absl::StrCat("opa cluster name must be provided in plugin "
                     "configuration JSON string: ",
                     configuration_data->view()));
    return false;
  }


  return true;
}

FilterHeadersStatus PluginContext::onRequestHeaders(uint32_t, bool) {
  if (!rootContext()->initialized()) {
    return FilterHeadersStatus::Continue;
    ;
  }
  auto *root_context = getRootContext();
  OPAPayload payload;
  // construct payload struct
  getValue({"connection", "uri_san_peer_certificate"}, &payload.source_principal);
  getValue({"node", "metadata", "WORKLOAD_NAME"}, &payload.destination_workload);
  getValue({"request", "method"}, &payload.request_method);
  getValue({"request", "url_path"}, &payload.request_url_path);
  uint64_t payload_hash = 0;
  bool allowed = false;
  bool cache_hit = root_context->checkCache(payload, payload_hash, allowed);
  if cache_hit {
    if allowed {
      return FilterHeadersStatus::Continue;
    }
    sendLocalResponse(403, "OPA policy check denied", "", {});
    return FilterHeadersStatus::StopIteration;
  }

  // convert to JSON: copy each value into the JSON object
  json j;
  j["source_principcal"] = payload.source_principal;
  j["destination_service"] = payload.destination_service;
  j["request_operation"] = payload.request_operation;
  j["request_url_path"] = payload.request_url_path;

  // Convert payload proto to json string and send it to OPA server.
  std::string payloadString = j.dump(payloadJson)
  // keep
  // Construct http call to OPA server.
  HeaderStringPairs headers;
  HeaderStringPairs trailers;
  headers.emplace_back("content-type", "application/json");
  headers.emplace_back(":path", "/v1/data/test/allow");
  headers.emplace_back(":method", "POST");
  headers.emplace_back(":authority", root_context->opaServiceHost());

  // Get id of current context, which will be used in http callback.
  auto context_id = id();
  auto call_result = root_context->httpCall(
      root_context->opaClusterName(), headers, json_payload, trailers,
      5000,
      [this, context_id, payload_hash](uint32_t, size_t body_size, uint32_t) {
        // Callback is triggered inside root context. setEffectiveContext
        // swtich the background context from root context to the current
        // stream context.
        getContext(context_id)->setEffectiveContext();
        auto body =
            getBufferBytes(BufferType::HttpCallResponseBody, 0, body_size);
        // TODO: replace proto with struct
        // OPAResponse opa_response;
        // LOG_INFO("!!!!!!!!!!!!!! body is " + body->toString());    
        auto j = result.value();
        auto it = j.find("result");
        bool check_result = false;
        if (it != j.end()) {
          auto result_val = JsonValueAs<bool>(it.value());
          if (result_val.second != Wasm::Common::JsonParserResultDetail::OK) {
            // Failed to parse OPA response, response with server error.
            LOG_DEBUG(absl::StrCat(
                "cannot parse result in OPA response JSON string: ",
                body->view()));
            sendLocalResponse(500, "OPA policy check failed", "", {});
            return;
          }
          check_result = result_val.first.value();
        } else {
          // no result found in OPA response, response with server error.
          LOG_WARN(absl::StrCat(
              "result must be provided in OPA response JSON string: ",
              body->view()));
          sendLocalResponse(500, "OPA policy check failed", "", {});
          return;
        }
        addCache(payload_hash, check_result);
        if (!check_result) {
          // denied, send direct response.
          sendLocalResponse(403, "OPA policy check denied", "", {});
          return;
        }
        // allowed, continue request.
        continueRequest();
      });

  if (call_result != WasmResult::Ok) {
    LOG_WARN("cannot make call to OPA policy server");
    sendLocalResponse(500, "OPA policy check failed", "", {});
  }

  return FilterHeadersStatus::StopIteration;
}

#ifdef NULL_PLUGIN
}  // namespace Plugin
}  // namespace OPA
}  // namespace null_plugin
}  // namespace proxy_wasm
#endif
