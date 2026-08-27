# Shadowfetch Linux 3.5.0 workload research

Research checked 2026-08-27. Product conclusions use primary project
documentation and the 2025 Stack Overflow Developer Survey. Popularity is an
input, not an instruction to preinstall every tool.

## What production developers use

- Stack Overflow reports Docker's largest one-year usage increase in the 2025
  survey and describes it as near-universal. VS Code remains a leading
  development environment, Python gained strongly, FastAPI grew, PostgreSQL
  remains highly desired/admired, and `uv` was the most admired new tagged
  technology. Source: https://survey.stackoverflow.co/2025/technology
- The Dev Container specification standardizes development-specific container
  metadata and supports reuse in local development and CI. Source:
  https://containers.dev/overview
- Podman is a daemonless OCI container engine that can run as a non-privileged
  user. Source: https://docs.podman.io/en/latest/
- Distrobox integrates container environments tightly with the host and home;
  its own documentation says it is not a security sandbox. Source:
  https://distrobox.it/
- `uv` provides Python/project/version management, environments and lockfiles.
  Source: https://docs.astral.sh/uv/getting-started/features/

Decision: ship rootless Podman and useful base tools, offer focused signed
profiles for the heavier toolchains, create Dev Container-compatible project
metadata, and reserve Firebreak for the actual agent security boundary.

## What AI developers use and fear

- The Stack Overflow AI survey reports that agents are not yet mainstream,
  while 84% of agent users apply them to software development. Accuracy concerns
  reach 87% and security/privacy concerns reach 81%. Grafana/Prometheus and
  Sentry lead agent observability responses. Source:
  https://survey.stackoverflow.co/2025/ai
- Hugging Face's CLI supports dry-run downloads, explicit local directories and
  cache inspection/removal. Source:
  https://huggingface.co/docs/huggingface_hub/en/guides/cli
- JupyterLab is the current notebook/code/data environment from Project Jupyter.
  Source: https://jupyter.org/
- llama.cpp demonstrates broad CPU/GPU backends and an OpenAI-compatible local
  server, but Shadowfetch does not add a second model owner beside Buzz in this
  release. Source: https://github.com/ggml-org/llama.cpp/blob/master/README.md
- vLLM offers an OpenAI-compatible server for high-throughput serving, but it is
  a hardware-sensitive deployment choice and is not silently pulled into the
  desktop. Source: https://docs.vllm.ai/en/latest/getting_started/quickstart/
- ComfyUI provides an official Linux desktop path, but large model and plugin
  choices remain an optional post-install workflow. Source:
  https://docs.comfy.org/installation/desktop/linux

Decision: AI Lab includes notebooks, model provenance, Hugging Face tooling and
GPU diagnostics. Buzz remains the user-facing model chooser. Heavy runtimes,
weights and creative AI stacks stay explicit, measurable and removable.

## Agent tooling

- Codex, Claude Code, Grok Build and Cursor Agent all provide current Linux CLI
  paths. Shadowfetch keeps them independent and user-owned rather than bundling
  credentials or choosing an account for the user.
- Official references:
  - https://github.com/openai/codex/releases
  - https://code.claude.com/docs/en/installation
  - https://docs.x.ai/build/overview
  - https://docs.cursor.com/en/cli/installation

Decision: expose the tools together, pin and verify each artifact, make sign-in
native to each vendor, and launch risky work through Firebreak/checkpoints.

## Product synthesis

The flagship proposition is **Element Workbench**: Fire for connected
production speed, Ice for deliberate local privacy, and the same four project
profiles on both. A user receives a coherent starting environment and an agent
receives explicit boundaries. Nothing pretends that an AI-generated answer is
verification, that a development container is a security sandbox, or that a
downloaded model has a safe license without a recorded review.
