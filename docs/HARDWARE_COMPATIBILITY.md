# Hardware and environment compatibility report

Observed **2026-11-14, Asia/Calcutta**. These are read-only snapshots, not inference benchmarks. Raw machine diagnostics are retained locally and excluded from the published repository and release archive. The environment summary below records the validation platform without local user paths.

## Observed environment

| Component | Windows host | Existing Ubuntu WSL |
|---|---|---|
| OS | Windows 11, build 10.0.26300 | Ubuntu 26.04.1 LTS |
| Kernel | Windows | 6.18.58.1-microsoft-standard-WSL2 |
| Python | 3.14.7 | 3.14.4 |
| CPU | Intel family 6/model 183; 16 logical CPUs, 10 reported physical cores | 13th Gen Intel Core i5-13450HX; 16 logical virtual CPUs, 8 virtual cores reported |
| RAM total | 16,849,256,448 bytes ≈ 15.69 GiB | 8,164,081,664 bytes ≈ 7.60 GiB allocated |
| RAM available at snapshot | 4,104,482,816 bytes ≈ 3.82 GiB | 7,500,611,584 bytes ≈ 6.99 GiB |
| GPU | NVIDIA GeForce RTX 3050 6GB Laptop GPU | Same GPU exposed through WSL |
| VRAM | 6,144 MiB total; 6,001 MiB free | 6,144 MiB total; 6,001 MiB free |
| NVIDIA driver | 621.01 | 621.01 exposed through WSL |
| Ollama executable | Found | Not found |
| Loopback Ollama API | Online, installed model list available | Offline/unavailable at `127.0.0.1:11434` |
| Installed model | `gemma4:12b`, 11.9B parameters, Q4_K_M, 8,021,618,941-byte file ≈ 7.47 GiB | None discoverable through local API |
| Requested security tools | 0/14 executable paths found | 0/14 executable paths found |
| bubblewrap | Not found | `/usr/bin/bwrap` found |

CPU topology under WSL is virtualized and must not be interpreted as the physical hybrid-core topology of the host. Available memory varies with other applications. WSL's memory allocation is smaller than physical host RAM; the app must use what its own runtime actually sees.

## Compatibility assessment

**Phase 1:** suitable. The terminal shell, configuration, SQLAlchemy/Alembic database, authorization records and scope checks run without a model or GPU. Automated tests passed on both platforms; Linux remains the product target. The Windows run is development compatibility evidence, not a change to the Linux-first product direction.

**Future local inference:** the installed 12B model file already exceeds 6 GiB VRAM, and file size excludes KV cache, context and runtime allocations. It is not a conservative full-GPU fit. Partial offload/CPU inference may be possible depending on available system RAM, but no latency, throughput or quality claim has been tested. At the recorded available Windows RAM, it is not a safe default to load it for validation.

**Recommended first benchmark:** a locally installed 1.5B–4B instruction model in a Q4 quantization, one inference request at a time, 4096-token context and short outputs. This is an engineering starting point, not a validated model recommendation or a promise of security reasoning quality. Inspect the current model's actual capabilities and benchmark before adoption. Keep selected model configuration explicit; SHADOW never downloads or switches models automatically.

Increasing context and parallel inference increases memory requirements, as documented by [Ollama's context-length guide](https://docs.ollama.com/context-length) and [Ollama's FAQ](https://docs.ollama.com/faq). Ollama manages GPU offload and CPU fallback; Phase 1 only inventories hardware and model files. GPU detection does not prove that a particular model is using the GPU.

## Linux setup gaps

1. Ubuntu's Python initially lacked `ensurepip`/matching `python3-venv`. No OS packages were installed. Validation used an isolated workspace environment bootstrapped from a pip wheel. For normal installation, install the matching distribution venv package manually.
2. Windows Ollama being online does not imply Ubuntu loopback connectivity. Install/start Ollama inside the intended Linux environment or deliberately design a reviewed local access configuration later. Phase 1 permits only loopback origins and does not open Windows network bindings or change firewall rules.
3. Security tools are not installed in this environment. Availability hints are manual; no automatic tool installations or scans occurred.
4. A harmless bubblewrap namespace/mount startup was checked with `/usr/bin/true` during earlier work. This is not evidence that a security-tool adapter, egress confinement or exploit sandbox has passed validation; those features are absent from Phase 1.

## Still unverified

- Native Kali and Debian installations; native Ubuntu outside WSL.
- Python 3.11 minimum-version execution, despite compatible API choices and package requirements.
- Real interactive terminal emulator appearance beyond headless Textual tests and exported terminal render.
- Live inference, model intelligence, native tool calling, structured fallback accuracy, VRAM offload and CPU generation performance.
- Full clean installer/upgrade/uninstaller lifecycle on each target distribution.

No model, GPU driver, system package, network setting or WSL allocation was changed during this inspection.
