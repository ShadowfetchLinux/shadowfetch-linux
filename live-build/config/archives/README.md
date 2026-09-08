# live-build archives

`shadowfetch.list.chroot` points the chroot's apt at a local HTTP server
serving the freshly-built `repo/` directory at `http://127.0.0.1:8089/`.
The `Makefile` `iso` target starts that server before invoking `lb build`
and tears it down on exit.

`shadowfetch.list.binary` is the apt sources entry that ships *inside*
the final ISO, pointing at the public APT repo at
`https://shadowfetch.com/linux/apt/`. End users get incremental updates
through that URL.

Both entries carry `signed-by=/usr/share/keyrings/shadowfetch.gpg`. apt
therefore accepts these repositories only against that one key, and only
that key — never `[trusted=yes]`, which accepted the repository with no
signature check at all (W-19).

`make iso` stages three regenerable, uncommitted artifacts here from
`repo/shadowfetch.gpg.asc` (the armored export of the key reprepro signs
the repo with):

* `shadowfetch.key.chroot` / `shadowfetch.key.binary` — dearmored public
  key. live-build drops these into `/etc/apt/trusted.gpg.d/`; Phoenix's
  apt recovery contract still checks for the binary one.
* `shadowfetch-archive-keyring.deb` — a one-file package installing
  `/usr/share/keyrings/shadowfetch.gpg`. live-build `dpkg -i`s any
  `config/archives/*.deb` inside `lb_chroot_archives` *before* its first
  `apt-get update`, which is the only point early enough for a
  `signed-by=` path to resolve; it then persists into the squashfs, so the
  installed system resolves the same path.
