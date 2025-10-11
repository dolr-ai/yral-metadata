//! Helper utilities for working with Sentry
//!
//! This module provides convenient functions for capturing user context,
//! adding breadcrumbs, and tagging errors with additional information.

#![allow(dead_code)]

use sentry::protocol::{Level, User};

/// Set user context for the current Sentry scope
///
/// # Example
/// ```
/// use crate::sentry_helpers;
///
/// sentry_helpers::set_user_context("user_123", Some("user@example.com"), Some("john_doe"));
/// ```
pub fn set_user_context(id: &str, email: Option<&str>, username: Option<&str>) {
    sentry::configure_scope(|scope| {
        scope.set_user(Some(User {
            id: Some(id.to_string()),
            email: email.map(|e| e.to_string()),
            username: username.map(|u| u.to_string()),
            ..Default::default()
        }));
    });
}

/// Add a breadcrumb for tracking execution flow
///
/// # Example
/// ```
/// use crate::sentry_helpers;
///
/// sentry_helpers::add_breadcrumb("user_action", "User clicked submit button", Some("ui"));
/// ```
pub fn add_breadcrumb(message: &str, category: Option<&str>, data: Option<Vec<(&str, &str)>>) {
    let mut breadcrumb = sentry::Breadcrumb {
        message: Some(message.to_string()),
        level: Level::Info,
        ..Default::default()
    };

    if let Some(cat) = category {
        breadcrumb.category = Some(cat.to_string());
    }

    if let Some(data_vec) = data {
        for (key, value) in data_vec {
            breadcrumb.data.insert(key.to_string(), value.into());
        }
    }

    sentry::add_breadcrumb(breadcrumb);
}

/// Set additional tags for the current scope
///
/// # Example
/// ```
/// use crate::sentry_helpers;
///
/// sentry_helpers::set_tags(&[
///     ("canister_id", "abc123"),
///     ("operation", "update_metadata"),
/// ]);
/// ```
pub fn set_tags(tags: &[(&str, &str)]) {
    sentry::configure_scope(|scope| {
        for (key, value) in tags {
            scope.set_tag(key, value);
        }
    });
}

/// Set extra context data for the current scope
///
/// # Example
/// ```
/// use crate::sentry_helpers;
///
/// sentry_helpers::set_extra("request_payload", &json_string);
/// ```
pub fn set_extra(key: &str, value: &str) {
    sentry::configure_scope(|scope| {
        scope.set_extra(key, value.into());
    });
}

/// Capture a message with a specific level
///
/// # Example
/// ```
/// use crate::sentry_helpers;
///
/// sentry_helpers::capture_message("Something unusual happened", sentry::Level::Warning);
/// ```
pub fn capture_message(message: &str, level: Level) {
    sentry::capture_message(message, level);
}
