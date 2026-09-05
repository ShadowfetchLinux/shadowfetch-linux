# Element Workbench

Shadowfetch Linux 4.0.0 connects Mission Control to the same two Fire and Ice
operating postures and the
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

## From project to mission

Open Mission Control from the application menu, or choose **New mission** in
Workbench. Give the mission a title, project folder, workflow and instructions.
Use an existing project directly inside `~/Workspaces`; create one in
Workbench first. Choose one of:

- **Code & tests**: use a local Buzz model or your signed-in Codex CLI. Enter
  the actual test program and arguments. Inspect changes and test receipts
  before accepting the result.
- **Private report**: select text documents by their paths inside the project
  and an installed local Buzz model. Inspect the report and its source
  citations.
- **Media export**: select media paths inside the project. The engine performs
  a deterministic FFmpeg export and records validation in its receipt.

The connection selector makes external network access explicit. Codex needs
Fire for its cloud connection; local model and deterministic media workflows
can use Ice. A queued mission persists locally. Activity, Changes and Results
show its execution evidence. Failed and cancelled missions can be retried;
completed work waits for your review. Restore changes uses the mission's local
checkpoint and reports conflicts instead of silently overwriting newer work.

In Dolphin, right-click a project folder and choose **Shadowfetch Mission** to
open the same scoped creation form. Folders outside the workspace root are not
accepted; move or copy only the files you want the agent to use into a project.

**Grok Bot** has a featured page in Mission Control and a native installation
choice during Welcome. Its cloud tasks and account sign-in live in the official
Grok Bot app. The Grok Build coding CLI is a separate tool. No API keys or app
accounts are included in the distro.
