// I2P RE-WIRED - native unified privacy client (Rust/egui)
use eframe::egui::{self, Align2, Color32, CornerRadius, FontId, Rect, Sense, Stroke, Vec2, ViewportCommand};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem};
use tray_icon::{Icon as TrayIcon, TrayIcon as TrayHandle, TrayIconBuilder, TrayIconEvent};

const W: f32 = 390.0;
const H: f32 = 696.0;
const CH: f32 = 64.0;

struct Paths { warp: Option<PathBuf>, i2p_dir: Option<PathBuf>, bundle: Option<PathBuf>, tor: bool }

fn exists(p: &str) -> bool { std::path::Path::new(p).exists() }

fn detect() -> Paths {
    let pf = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
    let pf86 = std::env::var("ProgramFiles(x86)").unwrap_or_else(|_| r"C:\Program Files (x86)".into());
    let la = std::env::var("LOCALAPPDATA").unwrap_or_default();
    let warp = [format!(r"{pf}\Cloudflare\Cloudflare WARP\warp-cli.exe"),
                format!(r"{pf86}\Cloudflare\Cloudflare WARP\warp-cli.exe")]
        .iter().find(|p| exists(p)).map(PathBuf::from);
    let mut i2p_cands: Vec<String> = vec![];
    if let Ok(v) = std::env::var("REWIRED_I2P_DIR") { i2p_cands.push(v); }
    i2p_cands.extend(["B:\\i2p".into(), "C:\\i2p".into(), format!(r"{la}\\i2p"), format!(r"{pf}\\i2p"), format!(r"{pf86}\\i2p")]);
    let i2p_dir = i2p_cands.iter().find(|p| exists(&format!("{p}\\i2p.exe"))).map(PathBuf::from);
    let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf())).unwrap_or_default();
    let mut b_cands: Vec<PathBuf> = vec![];
    if let Ok(v) = std::env::var("REWIRED_BUNDLE_DIR") { b_cands.push(v.into()); }
    b_cands.extend([PathBuf::from(r"B:\i2pdbrowser"), exe_dir.join("..\\build"), exe_dir.join("..\\..")]);
    let bundle = b_cands.iter().find(|p| exists(&p.join("StartI2PdBrowser.bat").to_string_lossy())).cloned();
    let tor = TcpStream::connect_timeout(&"127.0.0.1:9050".parse().unwrap(), Duration::from_millis(400)).is_ok();
    Paths { warp, i2p_dir, bundle, tor }
}

fn warp_connected(warp: &PathBuf) -> bool {
    Command::new(warp).arg("status").output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("Connected")).unwrap_or(false)
}
fn i2p_up() -> bool {
    TcpStream::connect_timeout(&"127.0.0.1:7657".parse().unwrap(), Duration::from_millis(400)).is_ok()
}
fn tor_on() -> bool {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
        .and_then(|k| k.get_value::<u32, _>("ProxyEnable")).map(|v| v == 1).unwrap_or(false)
}
fn tor_toggle(on: bool) {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    if let Ok(k) = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", winreg::enums::KEY_ALL_ACCESS) {
        let _ = k.set_value("ProxyEnable", &u32::from(on));
        if on {
            let _ = k.set_value("ProxyServer", &"socks=127.0.0.1:9050".to_string());
            let _ = k.set_value("ProxyOverride", &TOR_PROXY_OVERRIDE.to_string());
        }
    }
}

const AUTOSTART_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const AUTOSTART_NAME: &str = "I2P RE-WIRED";
const TOR_PROXY_OVERRIDE: &str = "localhost;127.*;10.*;172.16.*;192.168.*;<local>;*.discord.com;*.discord.gg;*.discordapp.com;*.discordapp.net;*.steampowered.com;*.steamcontent.com;*.steamstatic.com";

fn autostart_enabled() -> bool {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(AUTOSTART_KEY)
        .and_then(|k| k.get_value::<String, _>(AUTOSTART_NAME))
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

fn set_autostart(on: bool) {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let exe = std::env::current_exe().ok();
    let Ok(k) = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(AUTOSTART_KEY, winreg::enums::KEY_ALL_ACCESS) else { return };
    if on {
        if let Some(exe) = exe {
            let _ = k.set_value(AUTOSTART_NAME, &format!("\"{}\"", exe.display()));
        }
    } else {
        let _ = k.delete_value(AUTOSTART_NAME);
    }
}

fn audit(paths: &Paths) -> String {
    let mut issues: Vec<String> = vec![];
    let pids: Vec<String> = Command::new("tasklist")
        .args(["/fi", "imagename eq javaw.exe", "/fo", "csv", "/nh"])
        .output().map(|o| String::from_utf8_lossy(&o.stdout).lines()
            .filter_map(|l| l.split(',').nth(1).map(|s| s.trim_matches('"').to_string())).collect())
        .unwrap_or_default();
    if pids.is_empty() { issues.push("i2p router not running".into()); }
    else if !i2p_up() { issues.push("i2p console not responding".into()); }
    else {
        let out = Command::new("netstat").args(["-ano", "-p", "tcp"]).output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
        let bad = exposed_listen_hosts(&out, &pids);
        if !bad.is_empty() { issues.push(format!("i2p listening on {}", bad.join(","))); }
    }
    if !paths.tor { issues.push("tor client not installed".into()); }
    if issues.is_empty() {
        format!("audit: clean - localhost-bound, no leaks{}", if tor_on() { ", tor proxy on" } else { "" })
    } else { format!("audit: {}", issues.join("; ")) }
}

fn exposed_listen_hosts(netstat_out: &str, pids: &[String]) -> Vec<String> {
    let mut bad: Vec<String> = vec![];
    for l in netstat_out.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() >= 5 && f[3] == "LISTENING" && pids.iter().any(|p| p == f[4]) {
            // f[1] = local addr "ip:port" or "[::1]:port"
            let host = if let Some(h) = f[1].strip_prefix('[') {
                h.split(']').next().unwrap_or("").to_string()
            } else {
                f[1].rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or_default()
            };
            let loopback = host == "127.0.0.1" || host == "::1" || host.starts_with("127.");
            if !loopback && !bad.contains(&host) { bad.push(host); }
        }
    }
    bad
}

fn load_icon() -> (egui::IconData, TrayIcon) {
    let img = image::load_from_memory(include_bytes!("icon.ico")).expect("icon");
    let rgba = img.to_rgba8();
    let (w, h) = rgba.dimensions();
    let raw = rgba.into_raw();
    let idata = egui::IconData { rgba: raw.clone(), width: w, height: h };
    let ticon = TrayIcon::from_rgba(raw, w, h).expect("tray icon");
    (idata, ticon)
}

enum RowKind { Tor, I2p, Browser, Restart, Autostart, Audit }

struct App {
    paths: Paths,
    warp_on: bool,
    autostart: bool,
    compact: bool,
    busy: bool,
    report: String,
    report_until: f64,
    last_refresh: f64,
    #[allow(dead_code)]
    tray: Option<TrayHandle>,
}

impl App {
    fn refresh(&mut self) { self.warp_on = self.paths.warp.as_ref().map(|w| warp_connected(w)).unwrap_or(false); }
    fn refresh_state(&mut self, ctx: &egui::Context) {
        let was = (self.warp_on, self.autostart);
        self.refresh();
        self.autostart = autostart_enabled();
        if was != (self.warp_on, self.autostart) { ctx.request_repaint(); }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let now = ctx.input(|i| i.time);
        // tray events
        while let Ok(ev) = MenuEvent::receiver().try_recv() {
            match ev.id.0.as_str() {
                "show" => { ctx.send_viewport_cmd(ViewportCommand::Visible(true)); }
                "exit" => { ctx.send_viewport_cmd(ViewportCommand::Close); }
                _ => {}
            }
        }
        while let Ok(ev) = TrayIconEvent::receiver().try_recv() {
            if matches!(ev, TrayIconEvent::DoubleClick { .. }) {
                ctx.send_viewport_cmd(ViewportCommand::Visible(true));
            }
        }
        // close request -> hide to tray
        if ctx.input(|i| i.viewport().close_requested()) {
            ctx.send_viewport_cmd(ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(ViewportCommand::Visible(false));
        }
        // 30s refresh while visible
        if now - self.last_refresh >= 30.0 {
            self.last_refresh = now; self.refresh_state(ctx);
        }
        // expire report
        if !self.report.is_empty() && now > self.report_until { self.report.clear(); }

        let mut want_compact = self.compact;
        let mut restore = false;

        egui::CentralPanel::default().frame(egui::Frame::NONE).show(ctx, |ui| {
            let rect = Rect::from_center_size(ctx.screen_rect().center(), Vec2::new(W, if self.compact { CH + 14.0 } else { H }));
            let p = ui.painter();
            p.rect_filled(rect, CornerRadius::same(18), Color32::from_rgba_premultiplied(24, 15, 20, 34));
            p.rect_stroke(rect, CornerRadius::same(18), Stroke::new(1.0_f32, Color32::from_rgba_premultiplied(255, 255, 255, 45)), egui::StrokeKind::Inside);

            // ---- titlebar ----
            let bar = Rect::from_min_size(rect.min + Vec2::new(14.0, 12.0), Vec2::new(rect.width() - 28.0, 34.0));
            let minus_r = Rect::from_min_size(bar.min, Vec2::splat(34.0));
            let x_r = Rect::from_min_size(egui::pos2(rect.max.x - 48.0, bar.min.y), Vec2::splat(34.0));
            let m = ui.interact(minus_r, egui::Id::new("minus"), Sense::click());
            let x = ui.interact(x_r, egui::Id::new("x"), Sense::click());
            for (r, hov, ch) in [(minus_r, m.hovered(), if self.compact { "+" } else { "-" }),
                                (x_r, x.hovered(), "x")] {
                p.rect_filled(r, CornerRadius::same(17), if hov { Color32::from_rgba_premultiplied(255,255,255,60) } else { Color32::from_rgba_premultiplied(255,255,255,22) });
                p.text(r.center(), Align2::CENTER_CENTER, ch, FontId::proportional(14.0), Color32::from_gray(235));
            }
            if m.clicked() { want_compact = !want_compact; }
            if x.clicked() { ctx.send_viewport_cmd(ViewportCommand::Visible(false)); }
            let t = "I2P RE-WIRED";
            let ts = p.layout_no_wrap(t.to_string(), FontId::proportional(14.0), Color32::WHITE).size();
            p.text(egui::pos2(rect.center().x - ts.x / 2.0, bar.center().y), Align2::LEFT_CENTER, t, FontId::proportional(14.0), Color32::from_white_alpha(245));

            // drag via titlebar gaps
            let drag = Rect::from_min_max(egui::pos2(minus_r.max.x + 8.0, bar.min.y), egui::pos2(x_r.min.x - 8.0, bar.max.y));
            if ui.interact(drag, egui::Id::new("dragbar"), Sense::drag()).drag_started() {
                ctx.send_viewport_cmd(ViewportCommand::StartDrag);
            }

            if self.compact { return; }

            // ---- ring ----
            let ring_c = egui::pos2(rect.center().x, rect.min.y + 190.0);
            let ring_r = 84.0;
            let ring_rect = Rect::from_center_size(ring_c, Vec2::splat(ring_r * 2.0));
            let rr = ui.interact(ring_rect, egui::Id::new("ring"), Sense::click());
            p.circle_filled(ring_c, ring_r + 14.0, if self.warp_on { Color32::from_rgba_premultiplied(56, 189, 248, 60) } else { Color32::from_rgba_premultiplied(255, 255, 255, 40) });
            p.circle_filled(ring_c, ring_r, Color32::from_rgba_premultiplied(255, 255, 255, 18));
            p.circle_stroke(ring_c, ring_r - 1.0_f32, Stroke::new(3.0_f32, if self.warp_on { Color32::from_rgb(125, 211, 252) } else { Color32::from_rgba_premultiplied(255, 255, 255, 90) }));
            p.text(ring_c, Align2::CENTER_CENTER, "RE-WIRED", FontId::proportional(14.0), Color32::from_white_alpha(245));
            if rr.clicked() && !self.busy {
                self.busy = true;
                if let Some(w) = &self.paths.warp {
                    if self.warp_on { let _ = Command::new(w).arg("disconnect").output(); }
                    else { let _ = Command::new(w).arg("connect").output(); }
                }
                restore = true;
            }

            // ---- state ----
            let (big, bigc, sub): (&str, Color32, String) = if self.paths.warp.is_none() {
                ("No fast lane", Color32::from_gray(200), "Install Cloudflare WARP (engine only).".into())
            } else if self.warp_on {
                ("Connected", Color32::from_rgb(186, 230, 253), "Your traffic exits at a Cloudflare datacenter.".into())
            } else {
                ("Disconnected", Color32::from_gray(200), "Fast lane is off. Real IP exposed.".into())
            };
            let sub = if !self.report.is_empty() { self.report.clone() } else { sub };
            p.text(egui::pos2(rect.center().x, rect.min.y + 322.0), Align2::CENTER_CENTER, big, FontId::proportional(18.0), bigc);
            let ss = p.layout_no_wrap(sub.clone(), FontId::proportional(12.0), Color32::from_white_alpha(170)).size();
            p.text(egui::pos2(rect.center().x - ss.x / 2.0, rect.min.y + 352.0), Align2::LEFT_CENTER, &sub, FontId::proportional(12.0), Color32::from_white_alpha(170));

            // ---- rows ----
            let defs: [(&str, RowKind); 6] = [
                ("RE-WIRED Mode (Tor)", RowKind::Tor),
                ("I2P console", RowKind::I2p),
                ("RE-WIRED browser", RowKind::Browser),
                ("Restart I2P router", RowKind::Restart),
                ("Launch with Windows", RowKind::Autostart),
                ("Security audit - local checks", RowKind::Audit),
            ];
            for (i, (label, kind)) in defs.iter().enumerate() {
                let label = if matches!(kind, RowKind::Autostart) && self.autostart {
                    format!("{}  (on)", label)
                } else { (*label).to_string() };
                let label = label.as_str();
                let rrect = Rect::from_min_size(egui::pos2(rect.min.x + 18.0, rect.min.y + 392.0 + i as f32 * 56.0), Vec2::new(rect.width() - 36.0, 48.0));
                let resp = ui.interact(rrect, egui::Id::new(format!("row{i}")), Sense::click());
                p.rect_filled(rrect, CornerRadius::same(14), if resp.hovered() { Color32::from_rgba_premultiplied(255,255,255,46) } else { Color32::from_rgba_premultiplied(255,255,255,20) });
                p.rect_stroke(rrect, CornerRadius::same(14), Stroke::new(1.0_f32, Color32::from_rgba_premultiplied(255,255,255,38)), egui::StrokeKind::Inside);
                p.text(rrect.min + Vec2::new(16.0, 24.0), Align2::LEFT_CENTER, label, FontId::proportional(13.0), Color32::from_white_alpha(242));
                p.text(rrect.max - Vec2::new(16.0, 24.0), Align2::RIGHT_CENTER, "›", FontId::proportional(15.0), Color32::from_white_alpha(140));
                if resp.clicked() {
                    match kind {
                        RowKind::Tor => {
                            if self.paths.tor { tor_toggle(!tor_on()); }
                            else { self.report = "Tor client not installed".into(); self.report_until = now + 6.0; }
                        }
                        RowKind::I2p => {
                            if let Some(d) = &self.paths.i2p_dir {
                                let h = d.join("docs").join("startconsole.html");
                                let url = if h.exists() { h.to_string_lossy().to_string() } else { "http://127.0.0.1:7657".into() };
                                let _ = Command::new("cmd").args(["/c", "start", "", &url]).spawn();
                            }
                        }
                        RowKind::Browser => {
                            if let Some(b) = &self.paths.bundle {
                                let bat = b.join("StartI2PdBrowser.bat");
                                if bat.exists() { let _ = Command::new("cmd").args(["/c", "start", "", &bat.to_string_lossy()]).current_dir(b).spawn(); }
                            }
                        }
                        RowKind::Restart => {
                            if let Some(d) = &self.paths.i2p_dir {
                                let _ = Command::new("taskkill").args(["/f", "/im", "javaw.exe"]).output();
                                std::thread::sleep(Duration::from_secs(2));
                                let _ = Command::new(d.join("i2p.exe")).current_dir(d).spawn();
                            }
                        }
                        RowKind::Audit => { self.report = audit(&self.paths); self.report_until = now + 8.0; }
                        RowKind::Autostart => {
                            set_autostart(!self.autostart);
                            self.autostart = autostart_enabled();
                            self.report = if self.autostart { "Starts with Windows".into() } else { "Removed from startup".into() };
                            self.report_until = now + 4.0;
                        }
                    }
                }
            }

            // footer
            p.text(egui::pos2(rect.center().x, rect.max.y - 22.0), Align2::CENTER_CENTER, "by Hashbrown", FontId::proportional(10.0), Color32::from_white_alpha(89));
        });

        if want_compact != self.compact {
            self.compact = want_compact;
            ctx.send_viewport_cmd(ViewportCommand::InnerSize(egui::vec2(W, if want_compact { CH + 14.0 } else { H })));
        }
        if restore { self.refresh(); }
    }
}

fn main() -> eframe::Result<()> {
    let (idata, tray_icon) = load_icon();
    let menu = Menu::new();
    let _ = menu.append(&MenuItem::with_id(MenuId::new("show"), "Show / Hide", true, None));
    let _ = menu.append(&MenuItem::with_id(MenuId::new("exit"), "Exit", true, None));
    let tray = TrayIconBuilder::new().with_menu(Box::new(menu)).with_icon(tray_icon)
        .with_tooltip("I2P RE-WIRED").with_icon_as_template(false).build().ok();
    let tray = tray.unwrap();
    tray.set_show_menu_on_left_click(false);

    let vp = egui::ViewportBuilder::default()
        .with_title("I2P RE-WIRED")
        .with_inner_size([W, H])
        .with_decorations(false)
        .with_transparent(true)
        .with_resizable(false)
        .with_icon(std::sync::Arc::new(idata));
    let opts = eframe::NativeOptions { viewport: vp, ..Default::default() };
    eframe::run_native("I2P RE-WIRED", opts, Box::new(|cc| {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        let mut app = App { paths: detect(), warp_on: false, autostart: autostart_enabled(), compact: false, busy: false,
            report: String::new(), report_until: 0.0, last_refresh: -30.0, tray: Some(tray) };
        app.refresh_state(&cc.egui_ctx);
        Ok(Box::new(app))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_hosts_flags_only_non_loopback_for_owned_pids() {
        let out = "  TCP    0.0.0.0:7657    0.0.0.0:0    LISTENING    4321\n  TCP    127.0.0.1:7658  0.0.0.0:0  LISTENING  4321\n  TCP    [::1]:9000     [::]:0     LISTENING    4321\n  TCP    192.168.1.5:9999 0.0.0.0:0 LISTENING  7777\n";
        let pids = vec!["4321".to_string()];
        assert_eq!(exposed_listen_hosts(out, &pids), vec!["0.0.0.0".to_string()]);
    }

    #[test]
    fn listen_hosts_ignores_other_pids_and_ipv6_loopback() {
        let out = "  TCP    10.0.0.2:80   0.0.0.0:0   LISTENING   111\n  TCP    [::1]:80      [::]:0      LISTENING   111\n";
        let pids = vec!["999".to_string()];
        assert!(exposed_listen_hosts(out, &pids).is_empty());
        let pids2 = vec!["111".to_string()];
        assert_eq!(exposed_listen_hosts(out, &pids2), vec!["10.0.0.2".to_string()]);
    }

    #[test]
    fn tor_override_keeps_local_and_game_traffic_direct() {
        for needle in ["<local>", "127.*", "*.discord.com", "*.steampowered.com"] {
            assert!(TOR_PROXY_OVERRIDE.contains(needle), "missing {needle}");
        }
    }
}
