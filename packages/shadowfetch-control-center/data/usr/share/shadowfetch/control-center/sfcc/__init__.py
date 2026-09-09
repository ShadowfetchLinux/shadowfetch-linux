"""sfcc - Shadowfetch Control Center and Mission Control modules.

The Control Center executable at /usr/bin/shadowfetch-control is a thin
front door: it answers --help/--version before any Qt import, handles the
terminal fallback, then hands over to sfcc.app.run().  Everything visual
lives here, one module per sidebar section, all drawing from sfcc.theme so
the sections read as one application.

Since Stage P the sidebar, the pages behind it and every accepted route word
come from ONE registry (sfcc.pages.REGISTRY), sfcc.desktop holds the facts that
need no Qt and no bus, and an out-of-tree page arrives through the plugin
contract in sfcc.plugins rather than by writing a module into this directory.

System metrics come from local D-Bus services (org.shadowfetch.Firewatch1,
com.shadowfetch.Ember1, org.opensuse.Snapper, org.shadowfetch.Fireproof1),
a local fact file (/var/lib/shadowfetch/hwscan.json), or a local command.
Mission and model helpers use the selected runtime and connection policy;
optional vendor setup and native applications have their own network behavior.
When a source is unavailable the page says so in plain words instead of
showing stale or invented numbers.
"""

__all__ = [
    "app",
    "busutil",
    "desktop",
    "pages",
    "plugins",
    "theme",
    "mission_client",
    "missions_page",
    "grok_bot_page",
    "guide_page",
    "workbench_page",
    "ember_page",
    "firewatch_page",
    "phoenix_page",
    "workspaces_page",
    "drivers_page",
    "software_page",
]
