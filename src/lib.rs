use std::{
    fs::{self, Metadata},
    os::linux::fs::MetadataExt,
    path::Path,
};

use cli::Args;
use input_parser::{Filter, FilterSet, PermissionBlock};
use util::print_access_error;

pub mod cli;
pub mod input_parser;
pub mod util;

pub fn run(config: &Args) -> anyhow::Result<()> {
    let basedir_meta = &config.base_dir.metadata()?;

    if !config.silent {
        println!("Base directory: {:?}", config.base_dir);

        if config.file_filter.is_none() && config.directory_filter.is_none() {
            println!("Using gid and uid of base directory");
            println!(
                "Allowed: u{} g{}",
                basedir_meta.st_uid(),
                basedir_meta.st_gid()
            );
        } else {
            if let Some(filter) = &config.directory_filter {
                for single_filter in &filter.filters {
                    println!("Allowed  (dir): {}", single_filter);
                }
            }

            if let Some(filter) = &config.file_filter {
                for single_filter in &filter.filters {
                    println!("Allowed (file): {}", single_filter);
                }
            }
        }

        println!("");
    }

    run_recursive(config, &config.base_dir, basedir_meta)?;

    Ok(())
}

pub fn run_recursive(
    config: &Args,
    current_path: &Path,
    base_dir_meta: &Metadata,
) -> anyhow::Result<()> {
    let current_meta = current_path.metadata()?;
    check_object(current_path, config, base_dir_meta, false)?;

    if current_meta.is_dir() {
        let children = match fs::read_dir(current_path) {
            Ok(value) => value,
            Err(err) => {
                print_access_error(&format!("accessing {:?}: {err}", current_path));
                return Ok(());
            }
        };

        for child in children {
            match child {
                Ok(value) => {
                    if value.path().is_symlink() {
                        if !config.ignore_symlinks {
                            if let Err(err) =
                                check_object(&value.path(), config, base_dir_meta, true)
                            {
                                print_access_error(&format!(
                                    "reading symlink {:?}: {}. The symlink might be broken.",
                                    value.path(),
                                    err
                                ));
                            }
                        }
                        continue;
                    }
                    run_recursive(config, &value.path(), base_dir_meta)
                }
                Err(err) => {
                    print_access_error(&format!("accessing child of {:?}: {err}", current_path));
                    continue;
                }
            }?;
        }
    }

    Ok(())
}

fn check_object(
    path: &Path,
    config: &Args,
    base_dir_meta: &Metadata,
    is_symlink: bool,
) -> anyhow::Result<()> {
    let metadata = path.metadata()?;
    let is_dir = metadata.is_dir();

    if is_dir && config.directory_filter.is_none() {
        return Ok(());
    }

    if metadata.is_file() && config.file_filter.is_none() {
        return Ok(());
    }

    let permissions = PermissionBlock::from(&metadata);

    let filters = match if is_dir {
        &config.directory_filter
    } else {
        &config.file_filter
    } {
        Some(value) => value,
        None => &FilterSet {
            filters: vec![Filter {
                user_owner: Some(base_dir_meta.st_uid()),
                group_owner: Some(base_dir_meta.st_gid()),
                permissions: None,
            }],
        },
    };

    let meta_uid = metadata.st_uid();
    let meta_gid: u32 = metadata.st_gid();

    for filter in &filters.filters {
        if let Some(filter_uid) = filter.user_owner {
            if filter_uid != meta_uid {
                continue;
            }
        }

        if let Some(filter_gid) = filter.group_owner {
            if filter_gid != meta_gid {
                continue;
            }
        }

        if let Some(filter_permissions) = &filter.permissions {
            if !filter_permissions.is_compatible(&permissions) {
                continue;
            }
        }

        // Filter applies completely
        return Ok(());
    }

    let prefix = if is_symlink {
        "l"
    } else {
        if is_dir {
            "d"
        } else {
            "-"
        }
    };

    println!(
        "{prefix}{} {: >5} {: >5} {}",
        permissions,
        meta_uid,
        meta_gid,
        path.to_string_lossy()
    );

    Ok(())
}
