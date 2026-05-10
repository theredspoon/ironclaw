use std::{
    env, error,
    ffi::OsString,
    fmt,
    path::{Component, Path, PathBuf},
};

/// Environment variable that selects the standalone Reborn state root.
pub const REBORN_HOME_ENV: &str = "IRONCLAW_REBORN_HOME";

/// Source used to resolve [`RebornHome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebornHomeSource {
    Env,
    Default,
}

impl RebornHomeSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::Env => REBORN_HOME_ENV,
            Self::Default => "default",
        }
    }
}

/// Resolved, validated state root for the standalone Reborn binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebornHome {
    path: PathBuf,
    source: RebornHomeSource,
}

impl RebornHome {
    pub fn resolve_from_env() -> Result<Self, RebornConfigError> {
        Self::resolve_from_env_parts(
            env::var_os(REBORN_HOME_ENV),
            env::var_os("HOME"),
            env::var_os("USERPROFILE"),
        )
    }

    pub fn resolve_from_env_parts(
        reborn_home: Option<OsString>,
        home: Option<OsString>,
        userprofile: Option<OsString>,
    ) -> Result<Self, RebornConfigError> {
        if let Some(raw_home) = reborn_home {
            validate_non_empty(&raw_home, REBORN_HOME_ENV)?;
            let path = PathBuf::from(raw_home);
            validate_absolute(&path, REBORN_HOME_ENV)?;
            validate_no_parent_components(&path, REBORN_HOME_ENV)?;
            validate_not_root(&path, REBORN_HOME_ENV)?;
            return Ok(Self {
                path,
                source: RebornHomeSource::Env,
            });
        }

        let mut first_error = None;
        for (raw_home, label) in [(home, "HOME"), (userprofile, "USERPROFILE")] {
            let Some(raw_home) = raw_home else {
                continue;
            };
            match default_home_from_candidate(raw_home, label) {
                Ok(path) => {
                    return Ok(Self {
                        path,
                        source: RebornHomeSource::Default,
                    });
                }
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }

        Err(first_error.unwrap_or(RebornConfigError::MissingHome))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn into_path(self) -> PathBuf {
        self.path
    }

    pub fn source(&self) -> RebornHomeSource {
        self.source
    }

    pub fn source_label(&self) -> &'static str {
        self.source.label()
    }
}

fn validate_non_empty(value: &OsString, name: &'static str) -> Result<(), RebornConfigError> {
    if value.as_os_str().is_empty() {
        return Err(RebornConfigError::EmptyPath { name });
    }
    Ok(())
}

fn default_home_from_candidate(
    raw_home: OsString,
    label: &'static str,
) -> Result<PathBuf, RebornConfigError> {
    validate_non_empty(&raw_home, label)?;
    let path = PathBuf::from(raw_home);
    validate_absolute(&path, label)?;
    validate_no_parent_components(&path, label)?;
    validate_not_root(&path, label)?;
    Ok(path.join(".ironclaw").join("reborn"))
}

fn validate_absolute(path: &Path, name: &'static str) -> Result<(), RebornConfigError> {
    if !path.is_absolute() {
        return Err(RebornConfigError::RelativePath {
            name,
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn validate_no_parent_components(path: &Path, name: &'static str) -> Result<(), RebornConfigError> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(RebornConfigError::ParentPath {
            name,
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn validate_not_root(path: &Path, name: &'static str) -> Result<(), RebornConfigError> {
    if path.parent().is_none() {
        return Err(RebornConfigError::RootPath {
            name,
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

/// Error returned when standalone Reborn boot configuration is invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RebornConfigError {
    EmptyPath { name: &'static str },
    RelativePath { name: &'static str, path: PathBuf },
    ParentPath { name: &'static str, path: PathBuf },
    RootPath { name: &'static str, path: PathBuf },
    MissingHome,
    InvalidProfile { name: &'static str, value: String },
}

impl fmt::Display for RebornConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPath { name } => write!(formatter, "{name} must not be empty"),
            Self::RelativePath { name, .. } => write!(formatter, "{name} must be an absolute path"),
            Self::ParentPath { name, .. } => {
                write!(
                    formatter,
                    "{name} must not contain parent directory components"
                )
            }
            Self::RootPath { name, .. } => write!(formatter, "{name} must not be filesystem root"),
            Self::MissingHome => write!(
                formatter,
                "HOME or USERPROFILE must be set when {REBORN_HOME_ENV} is unset"
            ),
            Self::InvalidProfile { name, value } => write!(
                formatter,
                "{name} must be one of local-dev, production, migration-dry-run; got {value:?}"
            ),
        }
    }
}

impl error::Error for RebornConfigError {}
