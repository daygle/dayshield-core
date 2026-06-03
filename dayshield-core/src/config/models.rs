//! Configuration models.
//!
//! All structs are serialisable / deserialisable with serde so they can be
//! written to JSON files on disk and exchanged over the REST API.

use chrono::{DateTime, NaiveDate, NaiveTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;
