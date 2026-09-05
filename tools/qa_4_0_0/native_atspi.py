#!/usr/bin/env python3
"""Inspect or activate observed native buttons in a logged-in QA guest.

Only reads button labels by default; never dumps entry values or document text.
The named button is freshly located and must be unique before activation.
"""
import argparse
import json
import dbus

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--app", default="buzz-desktop")
parser.add_argument("--click")
parser.add_argument("--fields", action="store_true", help="List editable field labels, never their values")
parser.add_argument("--field", help="Exact observed field label to fill")
parser.add_argument("--focus-field", help="Focus one observed input for native keyboard entry")
parser.add_argument("--text", help="Text to enter through the native editable-text action")
args = parser.parse_args()
session = dbus.SessionBus()
address = session.get_object("org.a11y.Bus", "/org/a11y/bus").GetAddress(dbus_interface="org.a11y.Bus")
bus = dbus.bus.BusConnection(address)
interface = "org.a11y.atspi.Accessible"
properties = "org.freedesktop.DBus.Properties"
registry = bus.get_object("org.a11y.atspi.Registry", "/org/a11y/atspi/accessible/root")
apps = []
for name, path in registry.GetChildren(dbus_interface=interface):
    obj = bus.get_object(name, path)
    if str(obj.Get(interface, "Name", dbus_interface=properties)) == args.app:
        apps.append((str(name), str(path)))
if len(apps) != 1:
    raise SystemExit("Expected one native app, found " + str(len(apps)))
seen = set()
buttons = []
fields = []


def walk(name, path, depth=0):
    if depth > 25 or (name, path) in seen or len(seen) > 1500:
        return
    seen.add((name, path))
    try:
        obj = bus.get_object(name, path)
        role = int(obj.GetRole(dbus_interface=interface))
        # WebKitGTK sometimes returns an empty GetRoleName despite a valid role.
        if role in (11, 35, 43, 62):  # combo box, menu item, push button, or link
            label = str(obj.Get(interface, "Name", dbus_interface=properties))
            buttons.append({"label": label, "bus": name, "path": path})
        if args.fields or args.field is not None or args.focus_field is not None:
            interfaces = [str(value) for value in obj.GetInterfaces(dbus_interface=interface)]
            if role == 79 or "org.a11y.atspi.EditableText" in interfaces:
                fields.append({"label": str(obj.Get(interface, "Name", dbus_interface=properties)), "bus": name, "path": path})
        for child_name, child_path in obj.GetChildren(dbus_interface=interface):
            walk(str(child_name), str(child_path), depth + 1)
    except dbus.DBusException:
        # Elements can disappear when the native app updates its page.
        return


walk(*apps[0])
if args.focus_field is not None:
    matches = [field for field in fields if field["label"] == args.focus_field]
    if len(matches) != 1:
        raise SystemExit("Require exactly one observed input")
    match = matches[0]
    obj = bus.get_object(match["bus"], match["path"])
    print(json.dumps({"field": args.focus_field, "focused": bool(obj.GrabFocus(dbus_interface="org.a11y.atspi.Component", timeout=3))}))
elif args.field is not None:
    matches = [field for field in fields if field["label"] == args.field]
    if len(matches) != 1 or args.text is None:
        raise SystemExit("Require exactly one observed field and explicit text")
    match = matches[0]
    obj = bus.get_object(match["bus"], match["path"])
    assert str(obj.Get(interface, "Name", dbus_interface=properties)) == args.field
    print(json.dumps({"field": args.field, "filled": bool(obj.SetTextContents(args.text, dbus_interface="org.a11y.atspi.EditableText", timeout=3))}))
elif args.click:
    matches = [button for button in buttons if button["label"] == args.click]
    if len(matches) != 1:
        raise SystemExit("Expected one observed matching button, found " + str(len(matches)))
    match = matches[0]
    obj = bus.get_object(match["bus"], match["path"])
    assert str(obj.Get(interface, "Name", dbus_interface=properties)) == args.click
    count = int(obj.Get("org.a11y.atspi.Action", "NActions", dbus_interface=properties, timeout=3))
    if count != 1:
        raise SystemExit("Expected one unambiguous button action")
    action = str(obj.GetName(0, dbus_interface="org.a11y.atspi.Action", timeout=3))
    print(json.dumps({"button": args.click, "action": action, "activated": bool(obj.DoAction(0, dbus_interface="org.a11y.atspi.Action", timeout=3))}))
else:
    print(json.dumps({"application": args.app, "buttons": buttons, "fields": fields}, indent=2))
