#![deny(missing_docs)]

//! v-m.io types

/// Boxed Future.
pub type BoxFut<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = T> + 'a + Send>>;

pub mod api;
pub mod srv;
