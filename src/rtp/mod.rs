use std::error::Error;
use std::fmt;

pub mod header;

#[derive(Debug)]
pub enum RtpError {
	HeaderError(&'static str)
}

impl Error for RtpError {
	fn description(&self) -> &str {
		match *self {
			RtpError::HeaderError(cause) => cause
		}
	}
}

impl fmt::Display for RtpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            // Both underlying errors already impl `Display`, so we defer to
            // their implementations.
            RtpError::HeaderError(cause) => write!(f, "Header Error: {}", cause),
        }
    }
}