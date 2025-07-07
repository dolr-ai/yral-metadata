pub mod handlers;
pub mod implementation;

#[cfg(test)]
mod tests;

// Re-export handlers for backward compatibility
pub use handlers::*;
// Re-export METADATA_FIELD from implementation
pub use implementation::METADATA_FIELD;
