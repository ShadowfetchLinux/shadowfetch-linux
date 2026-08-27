# Element Workbench

Shadowfetch Linux 3.5.0 turns Fire and Ice into two operating postures for the
same four production profiles:

- **Software Studio**: Python, TypeScript, rootless containers, database tools,
  and a Dev Container-ready project template.
- **AI Lab**: Buzz, JupyterLab, the Hugging Face CLI, model provenance, and GPU
  diagnostics. Model downloads remain explicit and are not embedded in the ISO.
- **Production Ops**: Podman, Buildah, Skopeo, Ansible, runbooks, and deployment
  receipts.
- **Creative AI**: Krita, Blender, Kdenlive, OBS, FFmpeg, raw photography tools,
  and provenance templates.

Fire is the connected, high-throughput posture. Ice is the private posture:
Firebreak agent sessions start without network access until the user grants it.
Both retain project-only writes, secret stripping, checkpoints, and receipts.

Nothing in Workbench silently downloads a model, creates an account, copies a
credential, publishes work, or grants an agent broader access. The graphical
page and `shadowfetch-workbench plan PROFILE` state disk, network, account and
accelerator consequences before installation.

Useful commands:

    shadowfetch-workbench list
    shadowfetch-workbench plan ai-lab
    shadowfetch-workbench install ai-lab
    shadowfetch-workbench create ai-lab my-project
    shadowfetch-workbench doctor ai-lab

Profile installs use the same root-owned package catalog as Welcome. They are
one APT transaction and receive an automatic Phoenix Point on a supported
Btrfs installation. Projects live under `~/Workspaces` and contain no secrets.
