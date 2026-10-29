// Host bridge around pinned BitCrack CUDA code (see LICENSE.BitCrack).
// stdin: scan START END CAP SECONDS BLOCKS THREADS POINTS HASH160 (hex integers).
// stdout: newline-delimited JSON only; native diagnostics go to stderr.
#include <cuda_runtime.h>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include "CudaKeySearchDevice.h"
#include "cudabridge.h"

cudaError_t setValidKeyCount(unsigned long long n);
using secp256k1::uint256;
using Clock = std::chrono::steady_clock;

static double elapsed(Clock::time_point start) {
    return std::chrono::duration<double>(Clock::now() - start).count();
}
static void check(cudaError_t err) {
    if(err != cudaSuccess) throw std::runtime_error(cudaGetErrorString(err));
}
static std::string jsonquote(const std::string &text) {
    std::string out = "\"";
    for(unsigned char c : text) {
        if(c == '"' || c == '\\') { out += '\\'; out += c; }
        else if(c >= 32) out += c;
    }
    return out + "\"";
}
static void emit(const std::string &json) { std::cout << json << std::endl; }
static uint256 hex(const std::string &text) {
    if(text.empty() || text.size() > 64 || text.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
        throw std::runtime_error("Invalid hexadecimal protocol field");
    return uint256(text);
}
static std::string coverage(uint256 count, uint256 next, double seconds) {
    std::ostringstream out;
    out << "\"checked\":" << jsonquote(count.toString(16)) << ",\"next\":" << jsonquote(next.toString(16))
        << ",\"elapsed\":" << std::setprecision(17) << seconds;
    return out.str();
}

static void scan(int device, std::istringstream &request, bool wallBudget) {
    std::string startText, endText, capText, hashText, extra;
    double seconds;
    int blocks, threads, points;
    if(!(request >> startText >> endText >> capText >> seconds >> blocks >> threads >> points >> hashText) || request >> extra)
        throw std::runtime_error("Invalid scan request");
    uint256 start = hex(startText), end = hex(endText), cap = hex(capText);
    if(start.isZero() || start.cmp(end) > 0 || end.cmp(secp256k1::N) >= 0 || cap.isZero()
        || cap.cmp(end - start + 1u) > 0 || seconds < 0 || !std::isfinite(seconds)
        || blocks <= 0 || blocks > 4096 || threads <= 0 || threads > 1024 || threads % 32
        || points <= 0 || points > 4096 || hashText.size() != 40
        || hashText.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
        throw std::runtime_error("Invalid scan bounds, duration, target or launch dimensions");
    const uint64_t batch = uint64_t(blocks) * threads * points;
    if(batch > (1u << 26)) throw std::runtime_error("CUDA batch exceeds supported memory budget");
    auto initialization = Clock::now();
    // The worker serves many requests; object destruction releases each request's
    // allocations. The separate upstream global inversion chain is freed below.
    auto engine = std::make_unique<CudaKeySearchDevice>(device, threads, points, blocks);
    engine->init(start, PointCompressionType::COMPRESSED, uint256(1));
    KeySearchTarget target;
    for(int i = 0; i < 5; ++i) target.value[i] = std::stoul(hashText.substr(i * 8, 8), nullptr, 16);
    engine->setTargets({target});
    emit("{\"type\":\"ready\",\"initialization\":" + std::to_string(elapsed(initialization)) + "}");
    auto began = Clock::now();
    uint256 count(0), next = start;
    std::string status, match;
    while(count.cmp(cap) < 0) {
        if(seconds > 0 && elapsed(wallBudget ? initialization : began) >= seconds) { status = "duration"; break; }
        uint256 remaining = cap - count;
        uint64_t valid = remaining.cmp(uint256(batch)) < 0 ? uint64_t(remaining.v[0]) + (uint64_t(remaining.v[1]) << 32) : batch;
        check(setValidKeyCount(valid));
        engine->doStep(); // Includes synchronization: a returned batch is confirmed.
        count = count + uint256(valid);
        next = start + count;
        std::vector<KeySearchResult> results;
        engine->getResults(results);
        for(auto &result : results) {
            if(result.privateKey.cmp(start) < 0 || result.privateKey.cmp(next) >= 0)
                throw std::runtime_error("GPU returned a key outside the confirmed prefix");
            match = result.privateKey.toString(16);
        }
        // A matching batch is acknowledged only by the terminal event. Python
        // must verify and durably record the key before advancing past it.
        if(!match.empty()) { status = "match"; break; }
        emit("{\"type\":\"progress\"," + coverage(count, next, elapsed(began)) + "}");
    }
    if(status.empty()) status = next.cmp(end) > 0 ? "exhausted" : "limit";
    emit("{\"type\":\"done\",\"status\":" + jsonquote(status) + "," + coverage(count, next, elapsed(began))
         + (match.empty() ? "" : ",\"match\":" + jsonquote(match)) + "}");
    engine.reset();
    cleanupChainBuf();
}

int main(int argc, char **argv) {
    try {
        int device = argc == 2 ? std::stoi(argv[1]) : 0;
        check(cudaSetDevice(device));
        cudaDeviceProp info;
        check(cudaGetDeviceProperties(&info, device));
        int driver;
        check(cudaDriverGetVersion(&driver));
        std::ostringstream uuid;
        for(unsigned char byte : info.uuid.bytes) uuid << std::hex << std::setw(2) << std::setfill('0') << unsigned(byte);
        emit("{\"type\":\"device\",\"protocol\":2,\"name\":" + jsonquote(info.name) + ",\"uuid\":" + jsonquote(uuid.str())
             + ",\"sm\":" + std::to_string(info.multiProcessorCount) + ",\"driver\":" + std::to_string(driver)
             + ",\"major\":" + std::to_string(info.major) + ",\"minor\":" + std::to_string(info.minor) + "}");
        std::string line;
        while(std::getline(std::cin, line)) {
            std::istringstream request(line);
            std::string command;
            request >> command;
            if(command != "scan" && command != "scan_wall") throw std::runtime_error("Unknown worker command");
            scan(device, request, command == "scan_wall");
        }
        return 0;
    } catch(const KeySearchException &exc) {
        emit("{\"type\":\"error\",\"message\":" + jsonquote(exc.msg) + "}");
    } catch(const cuda::CudaException &exc) {
        emit("{\"type\":\"error\",\"message\":" + jsonquote(exc.msg) + "}");
    } catch(const std::exception &exc) {
        emit("{\"type\":\"error\",\"message\":" + jsonquote(exc.what()) + "}");
    } catch(const std::string &exc) {
        emit("{\"type\":\"error\",\"message\":" + jsonquote(exc) + "}");
    }
    return 1;
}
