//! `Host` impls for `greentic:extension-hosting/{log,target,api}`.
//!
//! Thin adapters: every decision lives in [`crate::hosting::session`]. They
//! exist so the generated traits are implemented once, next to each other, and
//! so a call with no session (which cannot happen through the hosting linker)
//! fails closed instead of panicking.

use crate::host_bindings::hosting::greentic::extension_hosting::{api, log, target};
use crate::host_state::HostState;
use crate::hosting::session::{ApiError, LogLevel};

impl log::Host for HostState {
    fn log(&mut self, level: log::Level, message: String) {
        if let Some(s) = self.hosting.as_mut() {
            let level = match level {
                log::Level::Trace => LogLevel::Trace,
                log::Level::Debug => LogLevel::Debug,
                log::Level::Info => LogLevel::Info,
                log::Level::Warn => LogLevel::Warn,
                log::Level::Error => LogLevel::Error,
            };
            s.log(level, &message);
        }
    }
}

impl target::Host for HostState {
    fn get(&mut self, key: String) -> Option<String> {
        self.hosting.as_ref().and_then(|s| s.target_get(&key))
    }
}

impl api::Host for HostState {
    fn call(
        &mut self,
        endpoint_id: String,
        method: String,
        path: String,
        body: Option<Vec<u8>>,
        headers: Vec<(String, String)>,
    ) -> Result<api::Response, api::ApiError> {
        let Some(session) = self.hosting.as_mut() else {
            return Err(api::ApiError::NotDeclared);
        };
        session
            .call(&endpoint_id, &method, &path, body, headers)
            .map(|r| api::Response {
                status: r.status,
                headers: r.headers,
                body: r.body,
            })
            .map_err(|e| match e {
                ApiError::NotDeclared => api::ApiError::NotDeclared,
                ApiError::DeniedByPolicy => api::ApiError::DeniedByPolicy,
                ApiError::Timeout => api::ApiError::Timeout,
                ApiError::Transport => api::ApiError::Transport,
                ApiError::TooLarge => api::ApiError::TooLarge,
            })
    }
}
