//! # framework/
//!
//! **SHARED platform-abstraction + dispatcher layer.**
//!
//! - [`platform`]   — the [`Platform`] trait every conferencing vendor
//!   implements, plus [`PlatformSnapshot`].
//! - [`dispatcher`] — the routing layer that parses each frame once and hands
//!   it to the first platform whose `classify` claims it.
//!
//! This module contains no vendor logic at all; it is the generic spine that
//! lets Teams, Google Meet and future platforms coexist over one capture
//! pipeline.

pub mod dispatcher;
pub mod platform;

pub use platform::{Platform, PlatformSnapshot};
