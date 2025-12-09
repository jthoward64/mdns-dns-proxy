mod handler;
mod utils;

pub use handler::MdnsDnsHandler;
pub use utils::should_handle_domain;

#[cfg(test)]
mod tests;
