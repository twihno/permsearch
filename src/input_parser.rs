use std::{fmt::Display, fs::Metadata, os::unix::fs::MetadataExt, str::FromStr};

use anyhow::{anyhow, bail};

#[derive(Debug, PartialEq, Clone)]
pub struct PermissionBlock {
    pub user: PartialPermissionBlock,
    pub group: PartialPermissionBlock,
    pub other: PartialPermissionBlock,
}

impl PermissionBlock {
    pub fn is_compatible(&self, other: &Self) -> bool {
        self.user.is_compatible(&other.user)
            && self.group.is_compatible(&other.group)
            && self.other.is_compatible(&other.other)
    }
}

impl From<Metadata> for PermissionBlock {
    fn from(value: Metadata) -> Self {
        Self::from(&value)
    }
}

impl From<&Metadata> for PermissionBlock {
    fn from(value: &Metadata) -> Self {
        let mode = value.mode();

        let other = PartialPermissionBlock::from_st_mode_digit(mode % 8);
        let mode = mode / 8;
        let group = PartialPermissionBlock::from_st_mode_digit(mode % 8);
        let mode = mode / 8;
        let user = PartialPermissionBlock::from_st_mode_digit(mode % 8);

        Self { user, group, other }
    }
}

impl Display for PermissionBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.user.fmt(f)?;
        self.group.fmt(f)?;
        self.other.fmt(f)?;

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PermissionState {
    SET,
    UNSET,
    WILDCARD,
}

#[derive(Debug, PartialEq, Clone)]
pub struct PartialPermissionBlock {
    pub read: PermissionState,
    pub write: PermissionState,
    pub execute: PermissionState,
}

impl Display for PartialPermissionBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for state in [(self.read, "r"), (self.write, "w"), (self.execute, "x")] {
            match state {
                (PermissionState::SET, _) => write!(f, "{}", state.1)?,
                (PermissionState::UNSET, _) => write!(f, "-")?,
                (PermissionState::WILDCARD, _) => write!(f, "*")?,
            }
        }

        Ok(())
    }
}

impl PartialPermissionBlock {
    fn from_st_mode_digit(digit: u32) -> Self {
        assert!(
            digit <= 7,
            "{digit} is > 7 and therefore invalid in the \"st_mode\" variable"
        );

        let execute = if digit % 2 == 1 {
            PermissionState::SET
        } else {
            PermissionState::UNSET
        };
        let digit = digit / 2;
        let write = if digit % 2 == 1 {
            PermissionState::SET
        } else {
            PermissionState::UNSET
        };
        let digit = digit / 2;
        let read = if digit % 2 == 1 {
            PermissionState::SET
        } else {
            PermissionState::UNSET
        };

        Self {
            read,
            write,
            execute,
        }
    }

    fn safe_from_chars(chars: &str) -> anyhow::Result<Self> {
        if !chars.is_ascii() {
            bail!("Non-ascii characters provided.")
        }

        if chars.len() != 3 {
            bail!("Permission block has an invalid number of characters (!= 3).");
        }

        let mut permission_block = PartialPermissionBlock {
            read: PermissionState::UNSET,
            write: PermissionState::UNSET,
            execute: PermissionState::UNSET,
        };

        let string_chars: Vec<char> = chars.chars().collect();

        for iterator in &mut [
            (0, 'r', &mut permission_block.read),
            (1, 'w', &mut permission_block.write),
            (2, 'x', &mut permission_block.execute),
        ] {
            let character = string_chars.get(iterator.0).ok_or(anyhow!(
                "Weird error where a text of length 3 doesn't have a char {}.",
                iterator.0
            ))?;

            if ![iterator.1, '-', '*'].contains(character) {
                bail!(
                    "Invalid character \"{}\" at position {} in permission block \"{}\".",
                    character,
                    iterator.0,
                    chars
                );
            }

            match *character {
                '*' => *iterator.2 = PermissionState::WILDCARD,
                '-' => *iterator.2 = PermissionState::UNSET,
                _ => *iterator.2 = PermissionState::SET,
            }
        }

        Ok(permission_block)
    }

    fn is_compatible(&self, other: &Self) -> bool {
        for block in [
            (self.read, other.read),
            (self.write, other.write),
            (self.execute, other.execute),
        ] {
            if block.0 == PermissionState::WILDCARD || block.1 == PermissionState::WILDCARD {
                continue;
            }

            if block.0 != block.1 {
                return false;
            }
        }

        true
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Filter {
    pub user_owner: Option<u32>,
    pub group_owner: Option<u32>,
    pub permissions: Option<PermissionBlock>,
}

impl Display for Filter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts: Vec<String> = Vec::new();

        if let Some(uid) = self.user_owner {
            parts.push(format!("u{}", uid.to_string()));
        }

        if let Some(gid) = self.group_owner {
            parts.push(format!("g{}", gid.to_string()));
        }

        if let Some(permissions) = &self.permissions {
            parts.push(permissions.to_string());
        }

        write!(f, "{}", parts.join(" "))?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FilterSet {
    pub filters: Vec<Filter>,
}

impl FilterSet {
    #[must_use]
    fn new() -> Self {
        FilterSet {
            filters: Vec::new(),
        }
    }

    fn add(&mut self, filter: Filter) {
        self.filters.push(filter);
    }
}

impl FromStr for FilterSet {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self, Self::Err> {
        let mut filter_set: FilterSet = FilterSet::new();

        for part in s.split(',') {
            let permissions = {
                if regex::Regex::new(r"^((r|-|\*)(w|-|\*)(x|-|\*)){3}")?.is_match(part) {
                    let user = PartialPermissionBlock::safe_from_chars(
                        part.get(..3)
                            .ok_or(anyhow!("Failed to extract user permissions"))?,
                    )?;
                    let group = PartialPermissionBlock::safe_from_chars(
                        part.get(3..6)
                            .ok_or(anyhow!("Failed to extract group permissions"))?,
                    )?;
                    let other = PartialPermissionBlock::safe_from_chars(
                        part.get(6..9)
                            .ok_or(anyhow!("Failed to extract other permissions"))?,
                    )?;

                    Some(PermissionBlock { user, group, other })
                } else {
                    None
                }
            };
            let user_owner =
                if let Some(captures) = regex::Regex::new(r"^.*u(\d+).*$")?.captures(part) {
                    if let Some(first_capture) = captures.get(1) {
                        Some(first_capture.as_str().parse::<u32>()?)
                    } else {
                        None
                    }
                } else {
                    None
                };
            let group_owner =
                if let Some(captures) = regex::Regex::new(r"^.*g(\d+).*$")?.captures(part) {
                    if let Some(first_capture) = captures.get(1) {
                        Some(first_capture.as_str().parse::<u32>()?)
                    } else {
                        None
                    }
                } else {
                    None
                };

            if user_owner.is_none() && group_owner.is_none() && permissions.is_none() {
                continue;
            }

            filter_set.add(Filter {
                user_owner,
                group_owner,
                permissions,
            });
        }

        if filter_set.filters.is_empty() {
            bail!("No valid filter provided");
        }

        Ok(filter_set)
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::input_parser::{
        Filter, FilterSet, PartialPermissionBlock, PermissionBlock, PermissionState,
    };

    #[test]
    fn test_safe_from_chars() {
        assert!(PartialPermissionBlock::safe_from_chars("").is_err());
        assert!(PartialPermissionBlock::safe_from_chars("🦀").is_err());
        assert!(PartialPermissionBlock::safe_from_chars("00000000a").is_err());
        assert!(PartialPermissionBlock::safe_from_chars("000000000").is_err());
        assert!(PartialPermissionBlock::safe_from_chars("wwx").is_err());
        assert!(PartialPermissionBlock::safe_from_chars("w--").is_err());
        assert_eq!(
            PartialPermissionBlock::safe_from_chars("---").unwrap(),
            PartialPermissionBlock {
                read: PermissionState::UNSET,
                write: PermissionState::UNSET,
                execute: PermissionState::UNSET
            }
        );
        assert_eq!(
            PartialPermissionBlock::safe_from_chars("*--").unwrap(),
            PartialPermissionBlock {
                read: PermissionState::WILDCARD,
                write: PermissionState::UNSET,
                execute: PermissionState::UNSET
            }
        );
        assert_eq!(
            PartialPermissionBlock::safe_from_chars("r--").unwrap(),
            PartialPermissionBlock {
                read: PermissionState::SET,
                write: PermissionState::UNSET,
                execute: PermissionState::UNSET
            }
        );
        assert_eq!(
            PartialPermissionBlock::safe_from_chars("*-*").unwrap(),
            PartialPermissionBlock {
                read: PermissionState::WILDCARD,
                write: PermissionState::UNSET,
                execute: PermissionState::WILDCARD
            }
        );
        assert_eq!(
            PartialPermissionBlock::safe_from_chars("rwx").unwrap(),
            PartialPermissionBlock {
                read: PermissionState::SET,
                write: PermissionState::SET,
                execute: PermissionState::SET
            }
        );
        assert_eq!(
            PartialPermissionBlock::safe_from_chars("rw*").unwrap(),
            PartialPermissionBlock {
                read: PermissionState::SET,
                write: PermissionState::SET,
                execute: PermissionState::WILDCARD
            }
        );
    }

    #[test]
    fn test_all() {
        assert_eq!(
            FilterSet::from_str("rwx------").unwrap(),
            FilterSet {
                filters: vec![Filter {
                    user_owner: None,
                    group_owner: None,
                    permissions: Some(PermissionBlock {
                        user: PartialPermissionBlock {
                            read: PermissionState::SET,
                            write: PermissionState::SET,
                            execute: PermissionState::SET
                        },
                        group: PartialPermissionBlock {
                            read: PermissionState::UNSET,
                            write: PermissionState::UNSET,
                            execute: PermissionState::UNSET
                        },
                        other: PartialPermissionBlock {
                            read: PermissionState::UNSET,
                            write: PermissionState::UNSET,
                            execute: PermissionState::UNSET
                        }
                    })
                }]
            }
        );
        assert_eq!(
            FilterSet::from_str("g1000").unwrap(),
            FilterSet {
                filters: vec![Filter {
                    user_owner: None,
                    group_owner: Some(1000),
                    permissions: None
                }]
            }
        );
        assert_eq!(
            FilterSet::from_str("---------g1000").unwrap(),
            FilterSet {
                filters: vec![Filter {
                    user_owner: None,
                    group_owner: Some(1000),
                    permissions: Some(PermissionBlock {
                        user: PartialPermissionBlock {
                            read: PermissionState::UNSET,
                            write: PermissionState::UNSET,
                            execute: PermissionState::UNSET
                        },
                        group: PartialPermissionBlock {
                            read: PermissionState::UNSET,
                            write: PermissionState::UNSET,
                            execute: PermissionState::UNSET
                        },
                        other: PartialPermissionBlock {
                            read: PermissionState::UNSET,
                            write: PermissionState::UNSET,
                            execute: PermissionState::UNSET
                        }
                    })
                }]
            }
        );
        assert_eq!(
            FilterSet::from_str("---------g1000u1000").unwrap(),
            FilterSet {
                filters: vec![Filter {
                    user_owner: Some(1000),
                    group_owner: Some(1000),
                    permissions: Some(PermissionBlock {
                        user: PartialPermissionBlock {
                            read: PermissionState::UNSET,
                            write: PermissionState::UNSET,
                            execute: PermissionState::UNSET
                        },
                        group: PartialPermissionBlock {
                            read: PermissionState::UNSET,
                            write: PermissionState::UNSET,
                            execute: PermissionState::UNSET
                        },
                        other: PartialPermissionBlock {
                            read: PermissionState::UNSET,
                            write: PermissionState::UNSET,
                            execute: PermissionState::UNSET
                        }
                    })
                }]
            }
        );
        assert_eq!(
            FilterSet::from_str("---------u1000").unwrap(),
            FilterSet {
                filters: vec![Filter {
                    user_owner: Some(1000),
                    group_owner: None,
                    permissions: Some(PermissionBlock {
                        user: PartialPermissionBlock {
                            read: PermissionState::UNSET,
                            write: PermissionState::UNSET,
                            execute: PermissionState::UNSET
                        },
                        group: PartialPermissionBlock {
                            read: PermissionState::UNSET,
                            write: PermissionState::UNSET,
                            execute: PermissionState::UNSET
                        },
                        other: PartialPermissionBlock {
                            read: PermissionState::UNSET,
                            write: PermissionState::UNSET,
                            execute: PermissionState::UNSET
                        }
                    })
                }]
            }
        );
    }

    #[test]
    fn test_from_st_mode_digit() {
        assert_eq!(
            PartialPermissionBlock::from_st_mode_digit(0),
            PartialPermissionBlock {
                read: PermissionState::UNSET,
                write: PermissionState::UNSET,
                execute: PermissionState::UNSET
            }
        );
        assert_eq!(
            PartialPermissionBlock::from_st_mode_digit(1),
            PartialPermissionBlock {
                read: PermissionState::UNSET,
                write: PermissionState::UNSET,
                execute: PermissionState::SET
            }
        );
        assert_eq!(
            PartialPermissionBlock::from_st_mode_digit(2),
            PartialPermissionBlock {
                read: PermissionState::UNSET,
                write: PermissionState::SET,
                execute: PermissionState::UNSET
            }
        );
        assert_eq!(
            PartialPermissionBlock::from_st_mode_digit(3),
            PartialPermissionBlock {
                read: PermissionState::UNSET,
                write: PermissionState::SET,
                execute: PermissionState::SET
            }
        );
        assert_eq!(
            PartialPermissionBlock::from_st_mode_digit(4),
            PartialPermissionBlock {
                read: PermissionState::SET,
                write: PermissionState::UNSET,
                execute: PermissionState::UNSET
            }
        );
        assert_eq!(
            PartialPermissionBlock::from_st_mode_digit(5),
            PartialPermissionBlock {
                read: PermissionState::SET,
                write: PermissionState::UNSET,
                execute: PermissionState::SET
            }
        );
        assert_eq!(
            PartialPermissionBlock::from_st_mode_digit(6),
            PartialPermissionBlock {
                read: PermissionState::SET,
                write: PermissionState::SET,
                execute: PermissionState::UNSET
            }
        );
        assert_eq!(
            PartialPermissionBlock::from_st_mode_digit(7),
            PartialPermissionBlock {
                read: PermissionState::SET,
                write: PermissionState::SET,
                execute: PermissionState::SET
            }
        );
    }

    #[test]
    #[should_panic(expected = "8 is > 7 and therefore invalid in the \"st_mode\" variable")]
    fn test_from_st_mode_digit_panic() {
        let _ = PartialPermissionBlock::from_st_mode_digit(8);
    }
}
