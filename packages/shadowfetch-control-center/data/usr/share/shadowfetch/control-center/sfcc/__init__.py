"""sfcc - Shadowfetch Control Center and Mission Control modules.

The Control Center executable at /usr/bin/shadowfetch-control is a thin
front door: it answers --help/--version before any Qt import, handles the
terminal fallback, then hands over to sfcc.app.run().  Everything visual
lives here, one module per sidebar section, all drawing from sfcc.theme so
the sections read as one application.

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
    "theme",
    "ember_page",
    "firewatch_page",
    "phoenix_page",
    "agents_page",
    "drivers_page",
    "software_page",
]
