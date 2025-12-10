mod handler;
pub mod utils; // Make public for testing

pub use handler::MdnsDnsHandler;
pub use utils::should_handle_domain;

#[cfg(test)]
mod tests;
