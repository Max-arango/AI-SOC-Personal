// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::Manager;

mod commands;
mod state;

use commands::*;
use state::AppState;

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            // Initialize app state
            let app_state = AppState::new(app.handle().clone());
            app.manage(app_state);
            
            // Set up system tray
            #[cfg(desktop)]
            {
                use tauri::{SystemTray, SystemTrayEvent, SystemTrayMenu, CustomMenuItem, SystemTrayMenuItem};
                let quit = CustomMenuItem::new("quit".to_string(), "Quit");
                let show = CustomMenuItem::new("show".to_string(), "Show");
                let tray_menu = SystemTrayMenu::new()
                    .add_item(show)
                    .add_native_item(SystemTrayMenuItem::Separator)
                    .add_item(quit);
                let system_tray = SystemTray::new().with_menu(tray_menu);
                system_tray.to_owned().set_icon(app.default_window_icon().cloned()).unwrap();
                app.handle().system_tray().set_menu(tray_menu).unwrap();
            }
            
            Ok(())
        })
        .on_system_tray_event(|app, event| match event {
            SystemTrayEvent::MenuItemClick { id, .. } => match id.as_str() {
                "quit" => {
                    std::process::exit(0);
                }
                "show" => {
                    if let Some(window) = app.get_window("main") {
                        window.show().unwrap();
                        window.set_focus().unwrap();
                    }
                }
                _ => {}
            },
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            health_check,
            get_status,
            query_events,
            get_alerts,
            get_processes,
            get_network_connections,
            explain_alert,
            chat_ai,
            get_config,
            update_config,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}