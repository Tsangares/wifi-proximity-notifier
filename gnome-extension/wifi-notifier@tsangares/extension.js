// WiFi Notifier — top-bar indicator for the wifi-proximity-notifier daemon.
// Talks to the daemon's HTTP API (default http://127.0.0.1:5555).

import Clutter from 'gi://Clutter';
import GObject from 'gi://GObject';
import GLib from 'gi://GLib';
import Gio from 'gi://Gio';
import St from 'gi://St';
import Soup from 'gi://Soup';

import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PanelMenu from 'resource:///org/gnome/shell/ui/panelMenu.js';
import * as PopupMenu from 'resource:///org/gnome/shell/ui/popupMenu.js';

const API_BASE = 'http://127.0.0.1:5555';
const REFRESH_SECONDS = 30;

const Indicator = GObject.registerClass(
class WifiNotifierIndicator extends PanelMenu.Button {
    _init() {
        super._init(0.5, 'WiFi Notifier');

        this._session = new Soup.Session({timeout: 5});

        const box = new St.BoxLayout({style_class: 'panel-status-menu-box'});
        this._icon = new St.Icon({
            icon_name: 'network-wireless-symbolic',
            style_class: 'system-status-icon',
        });
        this._countLabel = new St.Label({
            text: '',
            y_align: Clutter.ActorAlign.CENTER,
            style: 'font-size: 0.9em; padding-left: 2px;',
        });
        box.add_child(this._icon);
        box.add_child(this._countLabel);
        this.add_child(box);

        // --- menu ---
        this._statusItem = new PopupMenu.PopupMenuItem('Connecting…', {
            reactive: false,
            style_class: 'popup-inactive-menu-item',
        });
        this.menu.addMenuItem(this._statusItem);

        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());

        this._soundSwitch = new PopupMenu.PopupSwitchMenuItem('Notification sounds', true);
        this._soundSwitch.connect('toggled', (_item, state) => this._setSound(state));
        this.menu.addMenuItem(this._soundSwitch);

        const dashItem = new PopupMenu.PopupImageMenuItem('Open Dashboard', 'web-browser-symbolic');
        dashItem.connect('activate', () => {
            Gio.AppInfo.launch_default_for_uri(`${API_BASE}/`, null);
        });
        this.menu.addMenuItem(dashItem);

        // Refresh when the menu opens, and on a slow background cadence.
        this.menu.connect('open-state-changed', (_menu, open) => {
            if (open)
                this._refresh();
        });
        this._timeoutId = GLib.timeout_add_seconds(
            GLib.PRIORITY_DEFAULT, REFRESH_SECONDS, () => {
                this._refresh();
                return GLib.SOURCE_CONTINUE;
            });
        this._refresh();
    }

    async _fetchJson(method, path, body = null) {
        const msg = Soup.Message.new(method, `${API_BASE}${path}`);
        if (body !== null) {
            msg.set_request_body_from_bytes('application/json',
                new GLib.Bytes(new TextEncoder().encode(JSON.stringify(body))));
        }
        const bytes = await this._session.send_and_read_async(
            msg, GLib.PRIORITY_DEFAULT, null);
        if (msg.get_status() !== Soup.Status.OK)
            throw new Error(`HTTP ${msg.get_status()}`);
        return JSON.parse(new TextDecoder().decode(bytes.get_data()));
    }

    async _refresh() {
        try {
            const [settings, devices] = await Promise.all([
                this._fetchJson('GET', '/api/settings'),
                this._fetchJson('GET', '/api/devices'),
            ]);
            const list = devices.devices ?? [];
            const active = list.filter(d => d.is_active).length;

            this._soundSwitch.setToggleState(settings.sound_enabled);
            this._countLabel.text = `${active}`;
            this._statusItem.label.text =
                `${active} of ${list.length} devices online`;
            this._icon.icon_name = 'network-wireless-symbolic';
            this._soundSwitch.setSensitive(true);
        } catch (_e) {
            this._countLabel.text = '';
            this._statusItem.label.text = 'Service unreachable';
            this._icon.icon_name = 'network-wireless-offline-symbolic';
            this._soundSwitch.setSensitive(false);
        }
    }

    async _setSound(enabled) {
        try {
            await this._fetchJson('POST', '/api/settings', {sound_enabled: enabled});
        } catch (_e) {
            // Revert the switch if the daemon didn't take it.
            this._soundSwitch.setToggleState(!enabled);
            Main.notify('WiFi Notifier', 'Could not reach the service to change sound.');
        }
    }

    destroy() {
        if (this._timeoutId) {
            GLib.source_remove(this._timeoutId);
            this._timeoutId = null;
        }
        this._session.abort();
        this._session = null;
        super.destroy();
    }
});

export default class WifiNotifierExtension extends Extension {
    enable() {
        this._indicator = new Indicator();
        Main.panel.addToStatusArea(this.uuid, this._indicator);
    }

    disable() {
        this._indicator?.destroy();
        this._indicator = null;
    }
}
