"""Reproducible Windows/MSVC build with explicit, checked upstream adaptations."""

import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent


def replace(path, old, new, count=1):
    content = path.read_text()
    if content.count(old) != count:
        raise RuntimeError(f"Pinned upstream patch no longer matches: {path}: {old}")
    path.write_text(content.replace(old, new))


def adapt(source):
    device = source / "CudaKeySearchDevice"
    # These device pointers alias mapped host allocations. Upstream freed both
    # aliases, leaving an invalid-free error that poisoned the next request.
    atomic = device / "CudaAtomicList.cu"
    replace(atomic, "cudaFree(_countDevPtr);", "// Alias of _countHostPtr; freed with cudaFreeHost only.", 2)
    replace(atomic, "cudaFree(_devPtr);", "// Alias of _hostPtr; freed with cudaFreeHost only.", 2)
    # Mask only hash/comparison work, preserving the full point-addition chain
    # required by batch inversion even when the final batch is partially active.
    kernel = device / "CudaKeySearchDevice.cu"
    replace(kernel, "__constant__ unsigned int _INC_X[8];",
            "__constant__ unsigned long long _VALID_KEYS;\n"
            "cudaError_t setValidKeyCount(unsigned long long n) { return cudaMemcpyToSymbol(_VALID_KEYS, &n, sizeof(n)); }\n"
            "__constant__ unsigned int _INC_X[8];")
    replace(kernel, "if(compression == PointCompressionType::COMPRESSED || compression == PointCompressionType::BOTH)",
            "if(((unsigned long long)i * gridDim.x * blockDim.x + blockIdx.x * blockDim.x + threadIdx.x) < _VALID_KEYS && "
            "(compression == PointCompressionType::COMPRESSED || compression == PointCompressionType::BOTH))", 2)
    # Keep counts in 256-bit integers; upstream multiplied iteration totals in
    # uint64_t, which would eventually wrap when searching large puzzle ranges.
    header = device / "CudaKeySearchDevice.h"
    replace(header, "uint64_t _iterations;", "uint64_t _iterations;\n    secp256k1::uint256 _completedKeys;")
    cpp = device / "CudaKeySearchDevice.cpp"
    replace(cpp, "_iterations = 0;", "_iterations = 0;\n    _completedKeys = secp256k1::uint256(0);")
    replace(cpp, "cudaCall(cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync));", "// Scheduling is selected before context creation by the worker.")
    replace(cpp, "_iterations++;", "if(_iterations < 2) _iterations++;\n    _completedKeys = _completedKeys + secp256k1::uint256(keysPerStep());")
    replace(cpp, "secp256k1::uint256((uint64_t)_blocks * _threads * _pointsPerThread * _iterations)", "_completedKeys")
    replace(cpp, "_startExponent + secp256k1::uint256(totalPoints) * _iterations * _stride", "_startExponent + _completedKeys * _stride")


def build(toolkit, original):
    if os.name != "nt":
        raise RuntimeError("This build script targets Windows/MSVC and CUDA sm_89")
    build_dir = ROOT / ".local" / "build"
    build_dir.mkdir(parents=True, exist_ok=True)
    source = build_dir / "BitCrack"
    shutil.copytree(original, source, dirs_exist_ok=True)
    adapt(source)
    vswhere = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
    vs = subprocess.check_output([str(vswhere), "-latest", "-products", "*", "-requires",
                                  "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"], text=True).strip()
    if not vs:
        raise RuntimeError("Visual Studio C++ build tools are required")
    vcvars = Path(vs) / "VC/Auxiliary/Build/vcvars64.bat"
    directories = ["util", "AddressUtil", "CryptoUtil", "secp256k1lib", "Logger",
                   "cudaUtil", "KeyFinderLib", "CudaKeySearchDevice", "cudaMath"]
    includes = [f'-I"{source / directory}"' for directory in directories]
    sources = [path for directory in directories if directory not in ("KeyFinderLib", "cudaMath")
               for path in sorted((source / directory).glob("*")) if path.suffix in (".cpp", ".cu")]
    # checksum.cpp is a legacy duplicate of the implementation in hash.cpp.
    sources = [path for path in sources if path.name != "checksum.cpp"]
    sources.append(ROOT / "native" / "worker.cpp")
    nvcc = toolkit / "bin/nvcc.exe"
    flags = ['-O3', '-std=c++17', '-arch=sm_89', '-rdc=true', '-Xcompiler=/O2,/EHsc,/MD',
             '-D_CRT_SECURE_NO_WARNINGS', *includes]
    commands = ["@echo off", f'call "{vcvars}" >nul', "if errorlevel 1 exit /b 1"]
    objects = []
    for path in sources:
        obj = build_dir / f"{path.parent.name}_{path.name}.obj"
        objects.append(obj)
        commands.extend([f'"{nvcc}" {" ".join(flags)} -c "{path}" -o "{obj}"',
                         "if errorlevel 1 exit /b 1"])
    output = build_dir / "puzzle_cuda.exe"
    commands.extend([f'"{nvcc}" -arch=sm_89 -rdc=true -Xcompiler=/MD -Xlinker=/NODEFAULTLIB:LIBCMT {" ".join(chr(34) + str(obj) + chr(34) for obj in objects)} bcrypt.lib -o "{output}"',
                     "if errorlevel 1 exit /b 1"])
    batch = build_dir / "build.cmd"
    batch.write_text("\n".join(commands) + "\n")
    subprocess.run(["cmd.exe", "/d", "/c", str(batch)], cwd=build_dir, check=True)
    manifest = {"upstream": json.loads((ROOT / "native/upstream.json").read_text()),
                "nvcc": subprocess.check_output([str(nvcc), "--version"], text=True),
                "visual_studio": vs, "flags": flags}
    (build_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"Built {output}")
