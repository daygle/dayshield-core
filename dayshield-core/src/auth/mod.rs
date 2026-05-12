//! Authentication & User Management subsystem.
//!
//! # Overview
//!
//! This module provides the full authentication stack for DayShield:
//!
//! - [`model`]      - [`User`] model and [`AuthError`] error type.
//! - [`password`]   - Argon2id password hashing and verification.
//! - [`storage`]    - Persistent user storage at `/etc/dayshield/admin.json`.
//! - [`session`]    - JWT session token creation and validation.
//! - [`middleware`] - Axum middleware that authenticates every request.
//!
//! The authentication middleware protects all routes except:
//! - `POST /auth/login`
//! - `GET  /system/status`
//! - `GET  /installer/*`

pub mod middleware;
pub mod model;
pub mod password;
pub mod session;
pub mod storage;
