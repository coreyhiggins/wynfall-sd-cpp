#include <cstdlib>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "httplib.h"

#include "async_jobs.h"
#include "common/common.h"
#include "common/resource_owners.hpp"
#include "routes.h"
#include "runtime.h"
#include "wynfall_guard.h"

#ifdef HAVE_INDEX_HTML
#include "frontend/dist/gen_index_html.h"
#endif

static void print_usage(const char* argv0, const std::vector<ArgOptions>& options_list) {
    std::cout << version_string() << "\n";
    std::cout << "Usage: " << argv0 << " [options]\n\n";
    std::cout << "Svr Options:\n";
    options_list[0].print();
    std::cout << "\nContext Options:\n";
    options_list[1].print();
    std::cout << "\nDefault Generation Options:\n";
    options_list[2].print();
}

static void parse_args(int argc,
                       const char** argv,
                       SDSvrParams& svr_params,
                       SDContextParams& ctx_params,
                       SDGenerationParams& default_gen_params) {
    std::vector<ArgOptions> options_vec = {
        svr_params.get_options(),
        ctx_params.get_options(),
        default_gen_params.get_options(),
    };

    if (!parse_options(argc, argv, options_vec)) {
        print_usage(argv[0], options_vec);
        exit(svr_params.normal_exit ? 0 : 1);
    }

    log_level = svr_params.log_level;
    log_color = svr_params.color;

    const bool random_seed_requested = default_gen_params.seed < 0;

    if (!svr_params.resolve_and_validate() ||
        !ctx_params.resolve_and_validate(IMG_GEN) ||
        !default_gen_params.resolve_and_validate(IMG_GEN,
                                                 ctx_params.lora_model_dir,
                                                 ctx_params.hires_upscalers_dir)) {
        print_usage(argv[0], options_vec);
        exit(1);
    }

    if (random_seed_requested) {
        default_gen_params.seed = -1;
    }
}

void sd_log_cb(enum sd_log_level_t level, const char* log, void* data) {
    SDSvrParams* svr_params = (SDSvrParams*)data;
    log_print(level, log, svr_params->log_level, svr_params->color);
}

int main(int argc, const char** argv) {
    if (argc > 1 && std::string(argv[1]) == "--version") {
        std::cout << version_string() << "\n";
        return EXIT_SUCCESS;
    }
    // Wynfall patch: --api-key-env NAME names the environment variable that holds this launch's key. The key never
    // travels on the command line, so it does not show in a process listing.
    std::string api_key_env;
    std::vector<const char*> kept_args;
    for (int i = 0; i < argc; i++) {
        if (i > 0 && std::string(argv[i]) == "--api-key-env" && i + 1 < argc) {
            api_key_env = argv[++i];
            continue;
        }
        kept_args.push_back(argv[i]);
    }
    argc = static_cast<int>(kept_args.size());
    argv = kept_args.data();

    SDSvrParams svr_params;
    SDContextParams ctx_params;
    // Preserve the CLI default while disabling cwd scans for sd-server.
    ctx_params.lora_model_dir.clear();
    SDGenerationParams default_gen_params;

    sd_set_log_callback(sd_log_cb, (void*)&svr_params);
    parse_args(argc, argv, svr_params, ctx_params, default_gen_params);

    // Wynfall patch: refuse to run without a key, and refuse any bind other than loopback.
    const char* key_value = api_key_env.empty() ? nullptr : std::getenv(api_key_env.c_str());
    const std::string api_key = key_value ? key_value : "";
    if (api_key.size() < 16) {
        std::cerr << "error: set --api-key-env to the name of an environment variable holding a key of 16 or more characters\n";
        return 2;
    }
    if (!wynfall::is_loopback_ip(svr_params.listen_ip)) {
        std::cerr << "error: this build listens on 127.0.0.1 only\n";
        return 2;
    }

    LOG_VERBOSE("version: %s", version_string().c_str());
    LOG_VERBOSE("%s", sd_get_system_info());
    LOG_VERBOSE("%s", svr_params.to_string().c_str());
    LOG_VERBOSE("%s", ctx_params.to_string().c_str());
    LOG_VERBOSE("%s", default_gen_params.to_string().c_str());

    sd_ctx_params_t sd_ctx_params = ctx_params.to_sd_ctx_params_t(false);
    SDCtxPtr sd_ctx(new_sd_ctx(&sd_ctx_params));

    if (sd_ctx == nullptr) {
        LOG_ERROR("new_sd_ctx_t failed");
        return 1;
    }

    std::mutex sd_ctx_mutex;

    std::vector<LoraEntry> lora_cache;
    std::mutex lora_mutex;
    std::vector<UpscalerEntry> upscaler_cache;
    std::mutex upscaler_mutex;
    AsyncJobManager async_job_manager;
    ServerRuntime runtime = {
        sd_ctx.get(),
        &sd_ctx_mutex,
        &svr_params,
        &ctx_params,
        &default_gen_params,
        &lora_cache,
        &lora_mutex,
        &upscaler_cache,
        &upscaler_mutex,
        &async_job_manager,
    };

    std::thread async_worker(async_job_worker, std::ref(runtime));

    httplib::Server svr;

    // Wynfall patch: the upstream handler that answered every origin and every preflight is gone. See wynfall_guard.h.
    const int guard_port = svr_params.listen_port;
    svr.set_pre_routing_handler([&api_key, guard_port](const httplib::Request& req, httplib::Response& res) {
        return wynfall::guard(req, res, api_key, guard_port);
    });

    std::string index_html;
#ifdef HAVE_INDEX_HTML
    index_html.assign(reinterpret_cast<const char*>(index_html_bytes), index_html_size);
#else
    index_html = "Stable Diffusion Server is running";
#endif
    register_index_endpoints(svr, svr_params, index_html);
    register_openai_api_endpoints(svr, runtime);
    register_sdapi_endpoints(svr, runtime);
    register_sdcpp_api_endpoints(svr, runtime);

    LOG_INFO("listening on: http://%s:%d\n", svr_params.listen_ip.c_str(), svr_params.listen_port);
    svr.listen(svr_params.listen_ip, svr_params.listen_port);

    {
        std::lock_guard<std::mutex> lock(async_job_manager.mutex);
        async_job_manager.stop = true;
    }
    async_job_manager.cv.notify_all();
    async_worker.join();
    return 0;
}
