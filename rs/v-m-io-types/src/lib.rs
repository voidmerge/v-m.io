#![deny(missing_docs)]

//! v-m.io types

pub mod api;

/// A test function.
pub fn test() {
    println!("yo");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanity() {
        test();
    }
}
