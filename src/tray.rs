//! The tray icon: a StatusNotifierItem on the session bus (what Waybar and
//! Omarchy's shell show), run by ksni on a thread of its own. What the user
//! picks goes to the window as a [`Command`]; the window says whether the
//! vault is unlocked, for the menu and the tooltip.

use std::sync::Arc;

#[derive(Clone, Copy, Debug)]
pub enum Command {
    /// A click on the icon: show the window, or hide it if it's in front.
    Toggle,
    Show,
    Lock,
    Quit,
}

pub struct Tray {
    pub unlocked: bool,
    send: Arc<dyn Fn(Command) + Send + Sync>,
}

impl Tray {
    pub fn new(send: impl Fn(Command) + Send + Sync + 'static) -> Self {
        Self {
            unlocked: false,
            send: Arc::new(send),
        }
    }
}

fn item(label: &str, enabled: bool, command: Command) -> ksni::MenuItem<Tray> {
    ksni::menu::StandardItem {
        label: label.into(),
        enabled,
        activate: Box::new(move |tray: &mut Tray| (tray.send)(command)),
        ..Default::default()
    }
    .into()
}

impl ksni::Tray for Tray {
    fn id(&self) -> String {
        crate::APP_ID.into()
    }

    fn title(&self) -> String {
        "Vord".into()
    }

    fn icon_name(&self) -> String {
        crate::APP_ID.into()
    }

    /// Running from a checkout, the icon is in data/, not the icon theme.
    fn icon_theme_path(&self) -> String {
        if cfg!(debug_assertions) {
            concat!(env!("CARGO_MANIFEST_DIR"), "/data/icons").into()
        } else {
            String::new()
        }
    }

    fn category(&self) -> ksni::Category {
        ksni::Category::ApplicationStatus
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: "Vord".into(),
            description: if self.unlocked { "Unlocked" } else { "Locked" }.into(),
            ..Default::default()
        }
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        (self.send)(Command::Toggle);
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        vec![
            item("_Show Vord", true, Command::Show),
            item("_Lock", self.unlocked, Command::Lock),
            ksni::MenuItem::Separator,
            item("_Quit Vord", true, Command::Quit),
        ]
    }
}
