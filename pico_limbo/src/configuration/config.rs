use crate::configuration::boss_bar::BossBarConfig;
use crate::configuration::commands::CommandsConfig;
use crate::configuration::compression::CompressionConfig;
use crate::configuration::connection_config::ConnectionConfig;
use crate::configuration::env_placeholders::{EnvPlaceholderError, expand_env_placeholders};
use crate::configuration::fly_config::FlyConfig;
use crate::configuration::forwarding::ForwardingConfig;
use crate::configuration::game_mode_config::GameModeConfig;
use crate::configuration::server_list::ServerListConfig;
use crate::configuration::tab_list::TabListConfig;
use crate::configuration::title::TitleConfig;
use crate::configuration::world_config::WorldConfig;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::{fs, io};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("TOML serialization error: {0}")]
    TomlSerialize(#[from] toml::ser::Error),

    #[error("TOML deserialization error: {0}")]
    TomlDeserialize(#[from] toml::de::Error),

    #[error("Failed to apply environment placeholders: {0}")]
    EnvPlaceholder(#[from] EnvPlaceholderError),

    #[error("Invalid configuration: {0}")]
    Invalid(String),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MasivoReturnConfig {
    pub enabled: bool,
    pub control_address: String,
    pub shared_secret: String,
    pub return_host: String,
    pub return_port: u16,
    pub players_per_tick: usize,
}

impl Default for MasivoReturnConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            control_address: "127.0.0.1:8090".into(),
            shared_secret: String::new(),
            return_host: "play.example.com".into(),
            return_port: 25565,
            players_per_tick: 3,
        }
    }
}

impl MasivoReturnConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self
            .control_address
            .parse::<std::net::SocketAddr>()
            .is_err()
        {
            return Err(ConfigError::Invalid(
                "masivo_return.control_address must be an IP address and port".into(),
            ));
        }
        if self.shared_secret.len() < 32 {
            return Err(ConfigError::Invalid(
                "masivo_return.shared_secret must contain at least 32 characters".into(),
            ));
        }
        if self.return_host.is_empty()
            || !self
                .return_host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':'))
        {
            return Err(ConfigError::Invalid(
                "masivo_return.return_host is invalid".into(),
            ));
        }
        if self.return_port == 0 || self.players_per_tick == 0 {
            return Err(ConfigError::Invalid(
                "masivo_return return_port and players_per_tick must be positive".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn return_control_has_a_distinct_address_key() {
        let config = toml::Value::try_from(Config::default()).unwrap();
        let section = config.get("masivo_return").unwrap();
        assert!(section.get("control_address").is_some());
        assert!(section.get("bind").is_none());
    }
}

/// Application configuration, serializable to/from TOML.
#[derive(Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct Config {
    /// Server listening address and port.
    ///
    /// Specify the IP address and port the server should bind to.
    /// Use 0.0.0.0 to listen on all network interfaces.
    pub bind: String,

    pub forwarding: ForwardingConfig,

    pub world: WorldConfig,

    pub server_list: ServerListConfig,

    pub connection: ConnectionConfig,

    /// Message sent to the player after spawning in the world.
    pub welcome_message: String,

    pub action_bar: String,

    /// Sets the default game mode for players
    /// Valid values are: "survival", "creative", "adventure" or "spectator"
    pub default_game_mode: GameModeConfig,

    /// If set to true, will spawn the player in hardcode mode
    pub hardcore: bool,

    pub compression: CompressionConfig,

    pub tab_list: TabListConfig,

    pub fetch_player_skins: bool,

    pub reduced_debug_info: bool,

    pub fly: FlyConfig,

    pub accept_transfers: bool,

    pub boss_bar: BossBarConfig,

    pub title: TitleConfig,

    pub commands: CommandsConfig,

    pub masivo_return: MasivoReturnConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:25565".into(),
            server_list: ServerListConfig::default(),
            connection: ConnectionConfig::default(),
            welcome_message: "Welcome to PicoLimbo!".into(),
            action_bar: "Welcome to PicoLimbo!".into(),
            forwarding: ForwardingConfig::default(),
            default_game_mode: GameModeConfig::default(),
            world: WorldConfig::default(),
            hardcore: false,
            tab_list: TabListConfig::default(),
            fetch_player_skins: false,
            reduced_debug_info: false,
            boss_bar: BossBarConfig::default(),
            compression: CompressionConfig::default(),
            title: TitleConfig::default(),
            fly: FlyConfig::default(),
            accept_transfers: false,
            commands: CommandsConfig::default(),
            masivo_return: MasivoReturnConfig::default(),
        }
    }
}

/// Loads a `Config` from the given path.
/// If the file does not exist, it will be created (parent dirs too)
/// and populated with default values.
pub fn load_or_create<P: AsRef<Path>>(path: P) -> Result<Config, ConfigError> {
    let path = path.as_ref();

    if path.exists() {
        let raw_toml_str = fs::read_to_string(path)?;

        if raw_toml_str.trim().is_empty() {
            create_default_config(path)
        } else {
            let expanded_toml_str = expand_env_placeholders(&raw_toml_str)?;
            let cfg: Config = toml::from_str(expanded_toml_str.as_ref())?;
            cfg.masivo_return.validate()?;
            Ok(cfg)
        }
    } else {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        create_default_config(path)
    }
}

fn create_default_config<P: AsRef<Path>>(path: P) -> Result<Config, ConfigError> {
    let cfg = Config::default();
    let toml_str = toml::to_string_pretty(&cfg)?;
    fs::write(path, toml_str)?;
    Ok(cfg)
}
