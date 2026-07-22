#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::Manager;

mod commands;
mod state;

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let s = state::AppState::new(app.handle());
            app.manage(s);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_health,
            commands::get_status,
            commands::query_events,
            commands::get_alerts,
            commands::get_processes,
            commands::get_network_connections,
            commands::explain_alert,
            commands::chat_ai,
            commands::get_config,
            commands::update_config,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
