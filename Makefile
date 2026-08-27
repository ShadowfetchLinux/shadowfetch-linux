# Shadowfetch Linux — top-level build orchestration
#
# Common targets:
#   make deps       Install build dependencies (Debian host required)
#   make packages   Build all custom .deb packages
#   make repo       Generate the local APT repo from built packages
#   make iso        Build the bootable ISO (uses sudo; needs local repo)
#   make qemu       Boot the built ISO in QEMU for testing
#   make clean      Clean the live-build tree
#   make distclean  Wipe everything regenerable

SHELL := /bin/bash
VERSION  ?= 3.5.0
CODENAME ?= umbra
ISO_NAME := shadowfetch-$(VERSION)-amd64.iso
VERSION_TOKEN := $(subst .,_,$(VERSION))
PUBLIC_SITE ?= https://www.shadowfetchlinux.org
ARTIFACT_BASE ?= https://www.shadowfetch.com/linux

# Real source packages — each has its own debian/ tree.
# shadowfetch-meta builds two metapackages plus the upgrade-compatible,
# driver-free shadowfetch-nvidia setup package.
PACKAGES := \
	shadowfetch-meta \
	shadowfetch-welcome \
	shadowfetch-themes \
	shadowfetch-defaults \
	shadowfetch-branding \
	grub-btrfs \
	shadowfetch-ember \
	shadowfetch-firewatchd \
	shadowfetch-phoenix \
	shadowfetch-menus \
	shadowfetch-control-center \
	shadowfetch-fireproof \
	shadowfetch-hwscan \
	shadowfetch-fireline

# GPG key the APT repo signs with. Override with `make REPO_KEY_ID=...` if
# you've regenerated the key. The default matches the key on shadowfetch-linux.
REPO_KEY_ID ?= 8F13CE1535EE1F4A2916A1F73C5C900B7BE80CA1
# Generate an apt Valid-Until field automatically so clients do not break on
# stale metadata after publication. Reprepro accepts durations such as 14d.
REPO_VALID_FOR ?= 14d
# Publication gate minimum remaining Valid-Until lifetime: 24 hours.
REPO_MIN_VALID_FOR_SECONDS ?= 86400
# `sudo make iso` keeps SUDO_USER but changes HOME to /root. Point GnuPG at
# the invoking builder's keyring so repository and ISO signing stay reliable.
BUILDER_HOME := $(if $(SUDO_USER),$(shell getent passwd $(SUDO_USER) | cut -d: -f6),$(HOME))
BUILDER_USER := $(if $(SUDO_USER),$(SUDO_USER),$(shell id -un))
BUILDER_GROUP := $(shell id -gn $(BUILDER_USER))
GPG := gpg --homedir $(BUILDER_HOME)/.gnupg
REPREPRO := env GNUPGHOME=$(BUILDER_HOME)/.gnupg reprepro

# Port used to serve the local repo to the chroot during ISO build.
LOCAL_REPO_PORT ?= 8089

ROOT      := $(CURDIR)
BUILD_DIR := $(ROOT)/build
REPO_DIR  := $(ROOT)/repo
LB_DIR    := $(ROOT)/live-build
LB_BUILD_LOG := $(BUILD_DIR)/live-build-$(VERSION).log
LB_BUILD_MARKER := $(BUILD_DIR)/.live-build-$(VERSION)-started
QA_EVIDENCE_DIR := $(ROOT)/work/qa-$(VERSION)/evidence
ISO_GATE_LOG := $(QA_EVIDENCE_DIR)/iso/iso-gate.log
SOURCE_GATE := $(ROOT)/tools/source_gate_$(VERSION_TOKEN).py
PACKAGE_GATE := $(ROOT)/tools/package_gate_$(VERSION_TOKEN).py
ISO_GATE := $(ROOT)/tools/iso_gate_$(VERSION_TOKEN).py
ACCEPTANCE_TOOL := $(ROOT)/tools/verify_acceptance_$(VERSION_TOKEN).py
ACCEPTANCE_MANIFEST := $(ROOT)/qa/$(VERSION)/acceptance.json
RELEASE_DEBS := $(BUILD_DIR)/*_$(VERSION)-1_all.deb $(BUILD_DIR)/*_$(VERSION)-1_amd64.deb $(BUILD_DIR)/grub-btrfs_*_all.deb
PACKAGES_STAMP := $(BUILD_DIR)/.packages-$(VERSION)

R2_BUCKET ?= shadowfetch-linux
# Cloudflare R2 S3-compatible endpoint for this account.
# (wrangler can't PUT > 300 MiB; aws-cli with R2's S3 API handles multipart.)
R2_ENDPOINT ?= https://<CLOUDFLARE_ACCOUNT_ID>.r2.cloudflarestorage.com
R2_REGION   ?= auto

# Used by sync-from-linux (Mac-side flow): host + path to the build box.
LINUX_HOST ?= shadowfetch-linux
LINUX_PATH ?= ~/projects/shadowfetch-3.5.0

.PHONY: all help test source-gate package-gate iso-gate acceptance-audit deps packages repo iso sign pre-release-check publish qemu clean distclean \
        sync-from-linux deploy-worker ship stamp-version

all: iso

help:
	@echo "Shadowfetch build system"
	@echo "  make deps       Install required build dependencies"
	@echo "  make test       Run focused source and behavior checks"
	@echo "  make source-gate Run tests, parsers, linters and secret scans"
	@echo "  make package-gate Validate packages, signed repo and clean install"
	@echo "  make iso-gate   Validate the signed hybrid ISO and installed-image payload"
	@echo "  make acceptance-audit Validate the current release manifest and pending evidence"
	@echo "  make packages   Build all .deb packages"
	@echo "  make repo       Build local APT repository"
	@echo "  make iso        Build the bootable ISO (requires sudo)"
	@echo "  make qemu       Boot ISO in QEMU for testing"
	@echo "  make clean      Clean live-build artifacts"
	@echo "  make distclean  Wipe all regenerable files"

test:
	python3 -m unittest discover -s packages/shadowfetch-defaults/tests -v
	python3 -m unittest discover -s packages/shadowfetch-firewatchd/tests -v
	python3 -m unittest discover -s packages/shadowfetch-fireproof/tests -v
	python3 -m unittest discover -s packages/shadowfetch-hwscan/tests -v
	python3 packages/shadowfetch-fireline/tests/test_ai_ignition.py
	python3 packages/shadowfetch-fireline/tests/test_fireline_mcp.py
	python3 packages/shadowfetch-fireline/tests/test_checkpoint_roundtrip.py
	python3 -m unittest discover -s tools/tests -v

source-gate:
	@test -x $(SOURCE_GATE) || { echo "Missing source gate: $(SOURCE_GATE)" >&2; exit 1; }
	$(SOURCE_GATE)

package-gate: repo
	@test -x $(PACKAGE_GATE) || { echo "Missing package gate: $(PACKAGE_GATE)" >&2; exit 1; }
	$(PACKAGE_GATE)

acceptance-audit:
	@test -x $(ACCEPTANCE_TOOL) || { echo "Missing acceptance tool: $(ACCEPTANCE_TOOL)" >&2; exit 1; }
	@test -f $(ACCEPTANCE_MANIFEST) || { echo "Missing acceptance manifest: $(ACCEPTANCE_MANIFEST)" >&2; exit 1; }
	$(ACCEPTANCE_TOOL) --manifest $(ACCEPTANCE_MANIFEST) verify --allow-pending

deps:
	sudo apt-get update
	sudo apt-get install -y \
		live-build live-config live-boot \
		debhelper devscripts equivs dh-python lintian \
		reprepro gnupg \
		desktop-file-utils shellcheck podman \
		qemu-system-x86 qemu-utils \
		xorriso isolinux syslinux-common syslinux-utils \
		grub-pc-bin grub-efi-amd64-bin mtools \
		xz-utils python3 python3-yaml curl

packages: $(PACKAGES_STAMP)

# The version lives in exactly one place: VERSION above. It used to also live
# in shadowfetch-branding's data files, hand-edited, and 2.1.0 shipped an image
# whose os-release, version file and Calamares branding all said 2.0.1 -
# hooks/0016 derived the installer string correctly from a source of truth that
# was itself stale. A single source of truth that a human maintains is the same
# bug with one fewer copy, so the build stamps it now.
stamp-version:
	@printf '%s\n' '$(VERSION)' > $(ROOT)/packages/shadowfetch-branding/data/usr/share/shadowfetch/version
	@sed -i -E 's/[0-9]+\.[0-9]+\.[0-9]+/$(VERSION)/g' \
		$(ROOT)/packages/shadowfetch-branding/data/usr/share/shadowfetch/os-release.shadowfetch
	@for f in $(ROOT)/packages/shadowfetch-themes/data/usr/share/sddm/themes/umbra/metadata.desktop $(ROOT)/packages/shadowfetch-defaults/data/usr/share/doc/shadowfetch/LICENSES.md $(ROOT)/packages/shadowfetch-defaults/data/usr/share/doc/shadowfetch/SOURCES.md $(ROOT)/packages/shadowfetch-defaults/data/usr/bin/shadowfetch-element $(ROOT)/packages/shadowfetch-fireline/data/usr/bin/shadowfetch-firebreak; do \
		sed -i -E 's/\b[0-9]+\.[0-9]+\.[0-9]+\b/$(VERSION)/g' "$$f"; \
	done
	@echo ">>> stamped version $(VERSION) into branding, themes, docs and CLI surfaces"

$(PACKAGES_STAMP): stamp-version
	@mkdir -p $(BUILD_DIR)
	@for pkg in $(PACKAGES); do \
		echo ">>> Building $$pkg" ; \
		( cd $(ROOT)/packages/$$pkg && dpkg-buildpackage -us -uc -b ) || exit 1 ; \
		mv $(ROOT)/packages/*.deb $(BUILD_DIR)/ 2>/dev/null || true ; \
		mv $(ROOT)/packages/*.changes $(ROOT)/packages/*.buildinfo $(BUILD_DIR)/ 2>/dev/null || true ; \
	done
	@echo ">>> Built packages:"
	@ls -1 $(RELEASE_DEBS)
	@touch $@

repo: packages
	@rm -rf $(REPO_DIR)/db $(REPO_DIR)/dists $(REPO_DIR)/pool
	@mkdir -p $(REPO_DIR)/conf
	@printf '%s\n' \
		'Origin: Shadowfetch' \
		'Label: Shadowfetch' \
		'Codename: $(CODENAME)' \
		'Architectures: amd64 source' \
		'Components: main' \
		'Description: Shadowfetch Linux package repository' \
		'ValidFor: $(REPO_VALID_FOR)' \
		'DebIndices: Packages Release . .gz' \
		'DscIndices: Sources Release . .gz' \
		'SignWith: $(REPO_KEY_ID)' \
		> $(REPO_DIR)/conf/distributions
# Clean any prior pool entries for these packages so reprepro accepts re-includes.
	@for deb in $(RELEASE_DEBS); do \
		pkg=$$(dpkg-deb -f $$deb Package) ; \
		$(REPREPRO) -b $(REPO_DIR) remove $(CODENAME) $$pkg >/dev/null 2>&1 || true ; \
	done
# /linux/licensing promises complete corresponding source in main/source.
# Build it from cleaned copies and keep generated artifacts out of the tarballs.
	@rm -rf $(BUILD_DIR)/src && mkdir -p $(BUILD_DIR)/src
	@for pkg in $(PACKAGES); do \
		cp -a $(ROOT)/packages/$$pkg $(BUILD_DIR)/src/$$pkg ; \
		( cd $(BUILD_DIR)/src/$$pkg && fakeroot debian/rules clean >/dev/null ) || exit 1 ; \
		version=$$(dpkg-parsechangelog -l$(BUILD_DIR)/src/$$pkg/debian/changelog -SVersion) ; \
		upstream=$${version#*:} ; upstream=$${upstream%-*} ; \
		epoch=$$(date -u -d "$$(dpkg-parsechangelog -l$(BUILD_DIR)/src/$$pkg/debian/changelog -SDate)" +%s) ; \
		tar --sort=name --mtime="@$$epoch" --owner=0 --group=0 --numeric-owner \
			--exclude=$$pkg/debian --exclude=$$pkg/.git --exclude=$$pkg/.pc \
			-C $(BUILD_DIR)/src -cJf $(BUILD_DIR)/src/$${pkg}_$${upstream}.orig.tar.xz $$pkg ; \
		( cd $(BUILD_DIR)/src && dpkg-source -b $$pkg ) || exit 1 ; \
		GNUPGHOME=$(BUILDER_HOME)/.gnupg debsign --no-conf -k$(REPO_KEY_ID) \
			$(BUILD_DIR)/src/$${pkg}_$${version}.dsc || exit 1 ; \
		rm -rf $(BUILD_DIR)/src/$$pkg ; \
		$(REPREPRO) -b $(REPO_DIR) -T dsc remove $(CODENAME) $$pkg >/dev/null 2>&1 || true ; \
	done
	@for dsc in $(BUILD_DIR)/src/*.dsc; do \
		$(REPREPRO) -b $(REPO_DIR) includedsc $(CODENAME) $$dsc ; \
	done
	@for deb in $(RELEASE_DEBS); do \
		$(REPREPRO) -b $(REPO_DIR) includedeb $(CODENAME) $$deb ; \
	done
	@tmp=$$(mktemp -d) ; \
		trap 'rm -rf -- "$$tmp"' EXIT ; \
		for deb in $(RELEASE_DEBS); do dpkg-deb -f "$$deb" Package; done | sort -u > "$$tmp/expected-binary" ; \
		$(REPREPRO) -b $(REPO_DIR) list $(CODENAME) | awk '$$1 !~ /\|source:$$/ {print $$2}' | sort -u > "$$tmp/actual-binary" ; \
		for dsc in $(BUILD_DIR)/src/*.dsc; do sed -n 's/^Source: //p' "$$dsc"; done | sort -u > "$$tmp/expected-source" ; \
		$(REPREPRO) -b $(REPO_DIR) list $(CODENAME) | awk '$$1 ~ /\|source:$$/ {print $$2}' | sort -u > "$$tmp/actual-source" ; \
		diff -u "$$tmp/expected-binary" "$$tmp/actual-binary" ; \
		diff -u "$$tmp/expected-source" "$$tmp/actual-source" ; \
		echo ">>> Repo allowlist passed: $$(wc -l < "$$tmp/actual-binary") binary, $$(wc -l < "$$tmp/actual-source") source packages"
	@$(GPG) --armor --export $(REPO_KEY_ID) > $(REPO_DIR)/shadowfetch.gpg.asc
	@echo ">>> Repo built at $(REPO_DIR). Contents:"
	@$(REPREPRO) -b $(REPO_DIR) list $(CODENAME)

iso: repo
# A release build starts without any prior image or verification sidecars. If
# live-build fails later, no stale ISO can be mistaken for this invocation.
	@rm -f $(ROOT)/$(ISO_NAME) $(ROOT)/$(ISO_NAME).sha256 $(ROOT)/$(ISO_NAME).asc
	@rm -f $(LB_BUILD_LOG) $(LB_BUILD_MARKER) $(BUILD_DIR)/served-InRelease
# Stage a binary, dearmored GPG key for live-build's archives system.
	@mkdir -p $(LB_DIR)/config/archives
	@$(GPG) --dearmor < $(REPO_DIR)/shadowfetch.gpg.asc > $(LB_DIR)/config/archives/shadowfetch.key.chroot
	@cp $(LB_DIR)/config/archives/shadowfetch.key.chroot $(LB_DIR)/config/archives/shadowfetch.key.binary
# Clean the prior live-build output.
	@cd $(LB_DIR) && sudo lb clean
	@test ! -e $(LB_DIR)/binary/live/filesystem.squashfs || { echo "FATAL: lb clean left a stale squashfs" >&2; exit 1; }
	@touch $(LB_BUILD_MARKER)
# Serve the repo to the chroot. The old live-build binary_grub2 stage is not
# usable here, so the final hybrid image is assembled with grub-mkrescue below.
	@bash -c 'set -euo pipefail ; \
		cd "$(REPO_DIR)" ; \
		python3 -m http.server $(LOCAL_REPO_PORT) --bind 127.0.0.1 >"$(BUILD_DIR)/repo-server.log" 2>&1 & \
		SERVER_PID=$$! ; \
		cleanup() { kill "$$SERVER_PID" 2>/dev/null || true; wait "$$SERVER_PID" 2>/dev/null || true; } ; \
		trap cleanup EXIT INT TERM ; \
		sleep 1 ; \
		if ! kill -0 "$$SERVER_PID" 2>/dev/null; then cat "$(BUILD_DIR)/repo-server.log" >&2; echo "FATAL: local repository server did not start" >&2; exit 1; fi ; \
		curl --fail --silent --show-error --max-time 10 "http://127.0.0.1:$(LOCAL_REPO_PORT)/dists/$(CODENAME)/InRelease" > "$(BUILD_DIR)/served-InRelease" ; \
		cmp "$(BUILD_DIR)/served-InRelease" "$(REPO_DIR)/dists/$(CODENAME)/InRelease" ; \
		rm -f "$(BUILD_DIR)/served-InRelease" ; \
		echo ">>> Verified local repo server PID=$$SERVER_PID on :$(LOCAL_REPO_PORT)" ; \
		cd "$(LB_DIR)" ; \
		sudo lb config ; \
		sudo lb build 2>&1 | tee "$(LB_BUILD_LOG)"'
# Take ownership of live-build output and copy its kernel artifacts explicitly.
	@sudo chown -R $(BUILDER_USER):$(BUILDER_GROUP) $(LB_DIR)/binary
	@sudo chmod -R a+rX $(LB_DIR)/chroot/boot
# The squashfs is the first hard image gate.
	@test -f $(LB_DIR)/binary/live/filesystem.squashfs || { echo "FATAL: no squashfs in $(LB_DIR)/binary/live/" >&2; exit 1; }
	@test $(LB_DIR)/binary/live/filesystem.squashfs -nt $(LB_BUILD_MARKER) || { echo "FATAL: squashfs is not fresh for this build" >&2; exit 1; }
# Copy the newest kernel and initrd under predictable names.
	@KERNEL=$$(ls $(LB_DIR)/chroot/boot/vmlinuz-*-amd64 2>/dev/null | sort -V | tail -1) ; \
		INITRD=$$(ls $(LB_DIR)/chroot/boot/initrd.img-*-amd64 2>/dev/null | sort -V | tail -1) ; \
		[ -n "$$KERNEL" ] || { echo "FATAL: no kernel in $(LB_DIR)/chroot/boot/" >&2; exit 1; } ; \
		[ -n "$$INITRD" ] || { echo "FATAL: no initrd in $(LB_DIR)/chroot/boot/" >&2; exit 1; } ; \
		echo ">>> Found kernel: $$KERNEL" ; \
		echo ">>> Found initrd: $$INITRD" ; \
		cp "$$KERNEL" $(LB_DIR)/binary/live/vmlinuz ; \
		cp "$$INITRD" $(LB_DIR)/binary/live/initrd.img
# Replace live-build's GRUB configuration.
	@mkdir -p $(LB_DIR)/binary/boot/grub
	@cp $(ROOT)/live-build/config/grub.cfg $(LB_DIR)/binary/boot/grub/grub.cfg
# Install the Umbra GRUB theme.
	@mkdir -p $(LB_DIR)/binary/boot/grub/themes
	@cp -r $(ROOT)/live-build/config/grub-theme/umbra $(LB_DIR)/binary/boot/grub/themes/umbra
# live-build created SHA256SUMS before the kernel, initrd and final GRUB files
# above were replaced. Regenerate it over the exact tree sent to grub-mkrescue.
	@cd $(LB_DIR)/binary && \
		find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | \
		xargs -0 sha256sum > SHA256SUMS
	@cd $(LB_DIR)/binary && sha256sum --check --quiet SHA256SUMS
# Assemble the final BIOS and UEFI hybrid image.
	@echo ">>> Assembling final ISO with grub-mkrescue (BIOS + UEFI hybrid)"
	@rm -f $(ROOT)/$(ISO_NAME)
	@sudo grub-mkrescue \
		--output=$(ROOT)/$(ISO_NAME) \
		$(LB_DIR)/binary \
		-- -volid SHADOWFETCH
	@sudo chown $(BUILDER_USER):$(BUILDER_GROUP) $(ROOT)/$(ISO_NAME)
	@test $(ROOT)/$(ISO_NAME) -nt $(LB_BUILD_MARKER) || { echo "FATAL: ISO is not fresh for this build" >&2; exit 1; }
	@echo ">>> Built $(ISO_NAME)"
	@ls -lh $(ROOT)/$(ISO_NAME)
	@cd $(ROOT) && sha256sum $(ISO_NAME) > $(ISO_NAME).sha256
	@cd $(ROOT) && sha256sum --check $(ISO_NAME).sha256
	@echo ">>> SHA256: $$(cat $(ROOT)/$(ISO_NAME).sha256)"
	@$(MAKE) sign
	@$(MAKE) iso-gate

iso-gate:
	@mkdir -p $(dir $(ISO_GATE_LOG))
	@test -x $(ISO_GATE) || { echo "Missing ISO gate: $(ISO_GATE)" >&2; exit 1; }
	@set -o pipefail; $(ISO_GATE) 2>&1 | tee $(ISO_GATE_LOG)

# Detached GPG signature so downloaders can verify with: gpg --verify <iso>.asc
sign:
	@if [ ! -f $(ROOT)/$(ISO_NAME) ]; then echo "No ISO at $(ROOT)/$(ISO_NAME) — run 'make iso' first" >&2; exit 1; fi
	@rm -f $(ROOT)/$(ISO_NAME).asc
	@$(GPG) --batch --yes --local-user $(REPO_KEY_ID) --armor --detach-sign --output $(ROOT)/$(ISO_NAME).asc $(ROOT)/$(ISO_NAME)
	@$(GPG) --batch --verify $(ROOT)/$(ISO_NAME).asc $(ROOT)/$(ISO_NAME)
	@echo ">>> Signed: $(ROOT)/$(ISO_NAME).asc"

# Validate release metadata and local repo hygiene before any publication.
pre-release-check: iso-gate
	@ROOT=$(ROOT) CODENAME=$(CODENAME) REPO_DIR=$(REPO_DIR) REPO_MIN_VALID_FOR_SECONDS=$(REPO_MIN_VALID_FOR_SECONDS) \
		$(ROOT)/tools/pre_release_check.sh

# Upload ISO + APT repo to R2 via aws-cli (R2's S3-compatible API).
# Requires: brew install awscli, and an R2 API token from the Cloudflare
# dashboard (R2 → Manage R2 API Tokens → Create) exported as:
#   AWS_ACCESS_KEY_ID=<R2 Access Key ID>
#   AWS_SECRET_ACCESS_KEY=<R2 Secret Access Key>
# aws-cli handles multipart automatically, so the 2.9 GB ISO uploads fine.
publish: pre-release-check
	@command -v aws >/dev/null || { echo "aws not installed. Run: brew install awscli" >&2; exit 1; }
	@test -n "$$AWS_ACCESS_KEY_ID" || { echo "AWS_ACCESS_KEY_ID not set (use your R2 API token Access Key ID)" >&2; exit 1; }
	@test -n "$$AWS_SECRET_ACCESS_KEY" || { echo "AWS_SECRET_ACCESS_KEY not set (use your R2 API token Secret Access Key)" >&2; exit 1; }
	@if [ ! -f $(ROOT)/$(ISO_NAME) ]; then echo "No ISO to publish ($(ROOT)/$(ISO_NAME))" >&2; exit 1; fi
	@if [ ! -f $(ROOT)/$(ISO_NAME).asc ]; then echo "No signature ($(ROOT)/$(ISO_NAME).asc) — run 'make sign'" >&2; exit 1; fi
	@echo ">>> Uploading small files first (sha256, signature, GPG key)"
	@aws --endpoint-url=$(R2_ENDPOINT) --region=$(R2_REGION) s3 cp $(ROOT)/$(ISO_NAME).sha256 s3://$(R2_BUCKET)/releases/$(ISO_NAME).sha256 --content-type "text/plain"
	@aws --endpoint-url=$(R2_ENDPOINT) --region=$(R2_REGION) s3 cp $(ROOT)/$(ISO_NAME).asc    s3://$(R2_BUCKET)/releases/$(ISO_NAME).asc    --content-type "application/pgp-signature"
	@aws --endpoint-url=$(R2_ENDPOINT) --region=$(R2_REGION) s3 cp $(REPO_DIR)/shadowfetch.gpg.asc s3://$(R2_BUCKET)/shadowfetch.gpg.asc --content-type "application/pgp-keys"
	@echo ">>> Mirroring APT repo (dists/ + pool/) to R2 apt/"
	@aws --endpoint-url=$(R2_ENDPOINT) --region=$(R2_REGION) s3 sync $(REPO_DIR)/dists s3://$(R2_BUCKET)/apt/dists --delete
	@aws --endpoint-url=$(R2_ENDPOINT) --region=$(R2_REGION) s3 sync $(REPO_DIR)/pool  s3://$(R2_BUCKET)/apt/pool  --delete
	@echo ">>> Uploading ISO ($(ISO_NAME), $$(du -h $(ROOT)/$(ISO_NAME) | cut -f1), multipart). Progress below."
	@aws --endpoint-url=$(R2_ENDPOINT) --region=$(R2_REGION) s3 cp $(ROOT)/$(ISO_NAME) s3://$(R2_BUCKET)/releases/$(ISO_NAME) --content-type "application/x-iso9660-image"
	@echo ">>> Done. Verify:"
	@echo "    open $(PUBLIC_SITE)/"
	@echo "    curl -I  $(ARTIFACT_BASE)/download/$(ISO_NAME)"
	@echo "    curl -sI $(ARTIFACT_BASE)/apt/dists/$(CODENAME)/InRelease"

qemu:
	qemu-system-x86_64 \
		-enable-kvm \
		-cpu host -smp 4 -m 8192 \
		-vga virtio -display gtk,gl=on \
		-device intel-hda -device hda-duplex \
		-net nic,model=virtio -net user \
		-drive file=$(ROOT)/$(ISO_NAME),media=cdrom,readonly=on \
		-boot d

# ---- Mac-side deploy flow ----
# Run these from your Mac (where wrangler is logged in) to ship a release
# that was built on $(LINUX_HOST).

# Pull the latest ISO + checksum + signature + reprepro repo back from the
# Linux build box. Idempotent.
sync-from-linux:
	@echo ">>> Pulling ISO + repo from $(LINUX_HOST):$(LINUX_PATH)"
	@rsync -avzhP $(LINUX_HOST):$(LINUX_PATH)/shadowfetch-*.iso $(ROOT)/ 2>/dev/null || echo "(no ISO yet on Linux box)"
	@rsync -avzhP $(LINUX_HOST):$(LINUX_PATH)/shadowfetch-*.iso.sha256 $(ROOT)/ 2>/dev/null || true
	@rsync -avzhP $(LINUX_HOST):$(LINUX_PATH)/shadowfetch-*.iso.asc $(ROOT)/ 2>/dev/null || true
	@rsync -avzh --delete $(LINUX_HOST):$(LINUX_PATH)/repo/ $(REPO_DIR)/
	@ls -lh $(ROOT)/shadowfetch-*.iso 2>/dev/null || echo "(no ISO present)"

# Deploy the shadowfetch-linux Worker. Requires `wrangler login` (one time) or CLOUDFLARE_API_TOKEN.
deploy-worker:
	@command -v wrangler >/dev/null || { echo "wrangler not installed. Run: brew install cloudflare-wrangler2" >&2; exit 1; }
	@cd $(ROOT)/web/shadowfetch-linux-worker && wrangler deploy

# Full Mac-side ship: pull artifacts, publish to R2, deploy Worker.
ship: sync-from-linux publish deploy-worker
	@echo ""
	@echo ">>> SHIPPED. Verify:"
	@echo "    open $(PUBLIC_SITE)/"
	@echo "    curl -I $(ARTIFACT_BASE)/download/$(ISO_NAME)"
	@echo "    curl -sI $(ARTIFACT_BASE)/apt/dists/$(CODENAME)/InRelease"

clean:
	-cd $(LB_DIR) && sudo lb clean
	-rm -rf $(BUILD_DIR)
	-rm -f $(LB_DIR)/config/archives/shadowfetch.key.*

distclean: clean
	-rm -rf $(REPO_DIR)/db $(REPO_DIR)/dists $(REPO_DIR)/pool $(REPO_DIR)/conf
	-rm -f $(REPO_DIR)/shadowfetch.gpg.asc
	-rm -f $(ROOT)/*.iso $(ROOT)/*.iso.sha256
