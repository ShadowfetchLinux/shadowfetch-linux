# Buzz on Shadowfetch Linux 4.0.0 Fire Edition

Shadowfetch offers [Buzz](https://github.com/block/buzz) as the shared workspace
for people and AI agents. Buzz is optional. The first-run wizard can install the
official desktop package and create a private local relay. Buzz then owns model
selection, download, and serving through its native Compute settings.

## Start

Open **Buzz** from the **Local AI** menu, or run:

    shadowfetch-buzz setup

The setup downloads Buzz Desktop 0.5.17 from Block's official GitHub release and
verifies its SHA-256 before installation. It then starts Buzz Relay 0.2.1 in
rootless Podman, bound to `127.0.0.1:3000`. PostgreSQL, Redis, MinIO, relay data,
and generated secrets remain inside the user's local container storage. Relay
secrets are stored with mode 600.

On the first launch, Shadowfetch copies `ws://127.0.0.1:3000` to the clipboard
for Buzz's **Join a community** screen. After the first profile creates its
starter channels, a one-time local helper enrolls that profile as the private
relay administrator. The helper acts only when the roster is empty and exactly
one first-owner candidate exists. It uses the profile's public key through
Buzz's official administration command; it never reads or exports the profile's
private identity key. Existing and ambiguous rosters are left untouched.

## Local model

Buzz may ask for default agent model settings during its own onboarding. To run
an open model on this machine, open **Settings > Compute** in Buzz. The **Share
compute** card surveys the hardware, preselects Buzz's recommended open model,
and shows the model source before any download. Enabling **Share this machine**
starts the download with visible progress and serves the selected model through
Buzz's loopback-only endpoint on `127.0.0.1:9337`.

Shadowfetch does not install a second model runtime or maintain a competing
model picker. This keeps the recommendation, download status, model inventory,
and agent configuration in one application.

Useful commands:

    shadowfetch-buzz status
    shadowfetch-buzz open
    shadowfetch-buzz stop
    shadowfetch-agent-doctor

## Storage

Buzz configuration and generated relay secrets:

    ~/.config/shadowfetch/buzz/

Local compose project and environment:

    ~/.local/share/shadowfetch/buzz/

Container volumes hold the relay database, cache, uploaded media, and Git data.
`shadowfetch-buzz stop` stops the relay without deleting any of these files.
Buzz manages downloaded model files separately as application data; remove a
model from Buzz rather than deleting application data by hand.

The one-time owner marker and private diagnostic log are stored under:

    ~/.local/state/shadowfetch/buzz/

## Privacy and scope

The Fire Edition relay and model endpoint are deliberately local-only. Installing
Buzz, pulling relay containers, and downloading a model require network access
to the named upstream services. To make Buzz reachable from another computer,
use a properly authenticated TLS deployment from Buzz's official self-hosting
documentation; do not change a local bind address to `0.0.0.0` without
authentication and a firewall policy.

Buzz is an independent Apache-2.0 project built by Block. Shadowfetch is not
affiliated with or endorsed by Block.
