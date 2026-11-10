"""Bitwarden settings: explicit JSON import, without a connected account."""

import os
import stat
import threading

from gi.repository import Adw, GLib, Gtk

from ..bitwarden import MAX_EXPORT_BYTES, ImportError, parse_export
from ..i18n import _


class IntegrationsDialog(Adw.PreferencesDialog):
    """Preview a bounded export off the UI thread, then request daemon import."""

    def __init__(self, window):
        super().__init__(title=_("Settings"))
        self.window = window
        self._closed = False
        self._busy = False
        self.connect("closed", self._on_closed)
        page = Adw.PreferencesPage(title=_("Integrations"), icon_name="network-workgroup-symbolic")
        group = Adw.PreferencesGroup(
            title="Bitwarden",
            description=_("Import independent local copies from an official Bitwarden JSON export. "
                          "This does not connect your account or enable automatic synchronization."),
        )
        self.state = Adw.ActionRow(title=_("Connection"), subtitle=_("Not connected — manual import only"))
        group.add(self.state)
        row = Adw.ActionRow(title=_("Import Passkeys"), subtitle=_("Requires the login keyring and system authentication"))
        self.button = Gtk.Button(label=_("Choose JSON…"), valign=Gtk.Align.CENTER)
        self.button.connect("clicked", self._choose)
        row.add_suffix(self.button)
        group.add(row)
        group.add(Adw.ActionRow(title=_("Supported Passkeys"),
            subtitle=_("ES256 / P-256, discoverable, with a zero signature counter. "
                       "Older counters and unsupported keys are rejected.")))
        group.add(Adw.ActionRow(title=_("Security"), subtitle=_(
            "Your Bitwarden master password and session are never requested. "
            "Local copies use Linux verification and remain usable independently of Bitwarden. "
            "Delete the exported file securely after use; it contains private keys and other vault data.")))
        self.result = Adw.ActionRow(title=_("Last Import"), subtitle=_("No import in this window"))
        group.add(self.result)
        page.add(group)
        self.add(page)

    def _on_closed(self, *args):
        self._closed = True

    def _choose(self, *args):
        if self._busy:
            return
        dialog = Gtk.FileDialog(title=_("Choose Bitwarden JSON Export"))
        filter_ = Gtk.FileFilter()
        filter_.set_name(_("JSON exports"))
        filter_.add_pattern("*.json")
        dialog.set_default_filter(filter_)
        dialog.open(self.window, None, self._selected)

    def _selected(self, dialog, result):
        try:
            file = dialog.open_finish(result)
        except GLib.Error:
            return  # A cancelled picker is not an authentication failure.
        if self._closed:
            return
        path = file.get_path()
        if path is None:
            self._error(_("Choose a local JSON file"))
            return
        self._busy = True
        self.button.set_sensitive(False)
        self.result.set_subtitle(_("Reading export…"))

        def work():
            data, batch, error = None, None, None
            try:
                # Reject FIFOs, device files and unexpectedly large inputs.
                fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
                with os.fdopen(fd, "rb") as stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_EXPORT_BYTES:
                        raise ImportError("Choose a regular JSON file no larger than 16 MiB")
                    data = stream.read(MAX_EXPORT_BYTES + 1)
                batch = parse_export(data)
            except ImportError as e:
                error = str(e)
            except Exception:
                error = _("Could not read this export")
            GLib.idle_add(self._preview, data, batch, error)

        threading.Thread(target=work, name="bitwarden-preview", daemon=True).start()

    def _error(self, message):
        self.result.set_subtitle(message)
        self.window.toasts.add_toast(Adw.Toast(title=message))
        self._busy = False
        self.button.set_sensitive(True)

    def _preview(self, data, batch, error):
        self._busy = False
        self.button.set_sensitive(True)
        if self._closed:
            return False
        if error:
            self._error(error)
            return False
        rows = ["%s — %s" % (c.rp_id, c.user_name or c.display_name) for c in batch.credentials[:20]]
        if len(batch.credentials) > 20:
            rows.append(_("Additional passkeys are included in this batch."))
        if batch.errors:
            rows.append(_("Rejected entries:"))
            rows.extend(batch.errors[:20])
        body = _("%d compatible passkeys; %d rejected entries. Existing credentials are preserved. "
                 "Identical copies are skipped; conflicting IDs abort the whole import. "
                 "This is a local copy, not synchronization. Storage upgrades to v2; "
                 "older Linux Passkey versions cannot read it.\n\n") % (len(batch.credentials), len(batch.errors))
        body += "\n".join(rows)
        preview = Adw.AlertDialog(heading=_("Import Bitwarden Passkeys?"), body=body)
        preview.add_response("cancel", _("Cancel"))
        if batch.credentials:
            preview.add_response("import", _("Import Compatible Passkeys"))
            preview.set_response_appearance("import", Adw.ResponseAppearance.SUGGESTED)
        preview.set_default_response("cancel")
        preview.set_close_response("cancel")

        def responded(dialog, response):
            # Release the private export when the preview is dismissed.
            nonlocal data
            payload, data = data, None
            if response != "import" or self._closed:
                return
            if self.window.client is None:
                self._error(_("The passkey service is unavailable"))
                return
            self._busy = True
            self.button.set_sensitive(False)
            self.result.set_subtitle(_("Waiting for system authorization…"))
            self.window.client.import_bitwarden(payload, self._imported)

        preview.connect("response", responded)
        preview.present(self.window)
        return False

    def _imported(self, value, error):
        self._busy = False
        self.button.set_sensitive(True)
        if error:
            self._error(error.message)
        else:
            self.result.set_subtitle(_("%d passkeys imported") % value[0])
            self.window.refresh()
