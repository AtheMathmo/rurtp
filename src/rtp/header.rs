/// The RtpHeader module.
///
/// This module provides an implementation of the RtpHeader per [RFC-1889](https://tools.ietf.org/html/rfc1889).
/// The module is to be used to construct RtpHeaders from incoming network buffers.
///
/// The RTP header has the following format:
///
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |V=2|P|X|  CC   |M|     PT      |       sequence number         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           timestamp                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           synchronization source (SSRC) identifier            |
/// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
/// |            contributing source (CSRC) identifiers             |
/// |                             ....                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Extension Header                        |
/// |                             ....                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


use byteorder::{ByteOrder, NetworkEndian};
use super::RtpError;

/// The header for the RTP packet.
#[derive(Debug)]
pub struct Header {
	info: HeaderInfo,
	sequence: u16,
	timestamp: u32,
	ssrc_identifier: u32,
	csrc_identifiers: CSRCIdentifiers,
	extension: Option<HeaderExtension>,
}

impl Header {
	/// Construct the header from a network buffer.
	/// Note the buffer will be Big-Endian.
	///
	/// # Errors
	///
	/// If the header does not fit the format per [RFC-1889](https://tools.ietf.org/html/rfc1889)
	/// this method will return an Error.
	pub fn from_buf(mut header_buf: &[u8]) -> Result<Self, RtpError> {
		if header_buf.len() < 12 {
			return Err(RtpError::HeaderError("Buffer is too small to contain a valid header."));
		}
		// Extract the static header parts from 0..96 bits
		// Get the 16 bits for info
		let info = HeaderInfo(NetworkEndian::read_u16(header_buf));
		header_buf = &header_buf[2..];
		
		// Get bits for sequence
		let sequence = NetworkEndian::read_u16(header_buf);
		header_buf = &header_buf[2..];

		// Timestamp is 32 bits
		let timestamp = NetworkEndian::read_u32(header_buf);
		header_buf = &header_buf[4..];

		// SSRCS id is 32 bits
		let ssrc_id = NetworkEndian::read_u32(header_buf);
		header_buf = &header_buf[4..];

		// Get the number of csrc identifiers from the header info
		let csrc_count = info.csrc_count() as usize;

		// Check that we have room for the CSRC in buffer
		if header_buf.len() < csrc_count * 4 {
			return Err(RtpError::HeaderError("Buffer does not contain the specified number of CSRC identifiers."));
		}

		// Pull the csrc identifiers from the header
		let mut csrc_data : Vec<u32> = Vec::with_capacity(csrc_count);
		for _ in 0..csrc_count {
			csrc_data.push(NetworkEndian::read_u32(header_buf));
			header_buf = &header_buf[4..];
		}
		let csrc_ids = CSRCIdentifiers { identifiers: csrc_data };

		// Extract the headers
		let extension: Option<HeaderExtension>;
		if info.has_extension() {
			// We try to build the extension from the buffer - will return
			// an error if format is invalid.
			extension = Some(try!(HeaderExtension::from_buf(header_buf)));
		} else {
			extension = None;
		}

		Ok(Header {
			info: info,
			sequence: sequence,
			timestamp: timestamp,
			ssrc_identifier: ssrc_id,
			csrc_identifiers: csrc_ids,
			extension: extension,
		})
	}

	/// Return the header info.
	pub fn info(&self) -> &HeaderInfo {
		&self.info
	}

	/// Returns the sequence.
	pub fn sequence(&self) -> u16 {
		self.sequence
	}

	/// Returns the timestamp as a `u32`.
	pub fn timestamp(&self) -> u32 {
		self.timestamp
	}

	/// Returns the SSRC identifier.
	pub fn ssrc_identifier(&self) -> u32 {
		self.ssrc_identifier
	}

	/// Returns the CSRC identifiers.
	pub fn csrc_identifiers(&self) -> &Vec<u32> {
		&self.csrc_identifiers.identifiers
	}

	/// Return the header extension.
	pub fn extension(&self) -> &Option<HeaderExtension> {
		&self.extension
	}
}

/// The header info
///
/// These 16 bits contain information for the rest of the header.
#[derive(Debug)]
pub struct HeaderInfo(u16);

impl HeaderInfo {
	/// Gets the version from the header info.
	pub fn version(&self) -> u8 {
		(self.0 >> 14) as u8
	}

	/// Gets the padding flag from the header info.
	pub fn has_padding(&self) -> bool {
		((self.0 >> 13) & 0b1) == 1
	}

	/// Gets the extension flag from the header info.
	pub fn has_extension(&self) -> bool {
		((self.0 >> 12) & 0b1) == 1
	}

	/// Gets the number of CSRC identifiers in the header.
	pub fn csrc_count(&self) -> u8 {
		((self.0 >> 8) & 0b1111) as u8
	}

	/// Gets the marker flag from the header info.
	pub fn has_marker(&self) -> bool {
		((self.0 >> 7) & 0b1) == 1
	}

	/// Gets the payload type of the packet
	pub fn payload_type(&self) -> u8 {
		(self.0 & 0b1111111) as u8
	}
}

/// The CSRC identifiers
///
/// These are the contributing source IDs for when stream has been
/// generated from multiple sources.
#[derive(Debug)]
pub struct CSRCIdentifiers {
	identifiers: Vec<u32>
}

/// The header extension.
///
/// This contains the extension id, the extension length, and the 32bit chunks
/// of extension data.
#[derive(Debug)]
pub struct HeaderExtension {
	extension_id: u16,
	ehl: u16,
	extension: Vec<u32>,
}

impl HeaderExtension {
	/// Constructs a HeaderExtension from a network buffer.
	pub fn from_buf(mut extension_buf: &[u8]) -> Result<Self, RtpError> {
		if extension_buf.len() < 4 {
			return Err(RtpError::HeaderError("Header extension does not contain required info."));
		}

		let id = NetworkEndian::read_u16(extension_buf);
		extension_buf = &extension_buf[2..];
		let ehl = NetworkEndian::read_u16(extension_buf);
		extension_buf = &extension_buf[2..];

		if extension_buf.len() < ehl as usize * 4 {
			return Err(RtpError::HeaderError("Header extension does not contain specified number of blocks."))
		}

		let mut extension_data : Vec<u32> = Vec::with_capacity(ehl as usize);
		for _ in 0..ehl as usize {
			extension_data.push(NetworkEndian::read_u32(extension_buf));
			extension_buf = &extension_buf[4..];
		}

		Ok(HeaderExtension {
			extension_id: id,
			ehl: ehl,
			extension: extension_data,
		})
	}

	/// Return the extension id.
	pub fn extension_id(&self) -> u16 {
		self.extension_id
	}

	/// Return the extension header length. This is the number
	/// of elements in the extension data (blocks of 32 bits).
	pub fn extension_header_length(&self) -> u16 {
		self.ehl
	}

	/// Get the header extension. This is a `Vec` of `u32`.
	pub fn extension(&self) -> &Vec<u32> {
		&self.extension
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn small_header() {
		let buf : &[u8]= &[123, 123];

		let header = Header::from_buf(buf);

		assert!(header.is_err())
	}

	#[test]
	fn test_header_info_version() {
		let a = HeaderInfo(0b11 << 14);
		assert_eq!(a.version(), 3);

		let a = HeaderInfo(0b01 << 14);
		assert_eq!(a.version(), 1);

		let a = HeaderInfo(0b10 << 14);
		assert_eq!(a.version(), 2);
	}

	#[test]
	fn test_header_info_padding() {
		let a = HeaderInfo(0b1 << 13);
		assert_eq!(a.has_padding(), true);

		let a = HeaderInfo(0);
		assert_eq!(a.has_padding(), false);
	}


	#[test]
	fn test_header_info_extension() {
		let a = HeaderInfo(0b1 << 12);
		assert_eq!(a.has_extension(), true);

		let a = HeaderInfo(0);
		assert_eq!(a.has_extension(), false);
	}

	#[test]
	fn test_header_info_csrc_count() {
		let header_info_raw = 0b0000111100000000;
		let a = HeaderInfo(header_info_raw);
		assert_eq!(a.csrc_count(), 15);
	}

	#[test]
	fn test_header_info_marker() {
		let header_info_raw = 0b0000000010000000;
		let a = HeaderInfo(header_info_raw);
		assert_eq!(a.has_marker(), true);
	}


	#[test]
	fn test_header_info_payload_type() {
		let header_info_raw = 255;
		let a = HeaderInfo(header_info_raw);
		assert_eq!(a.payload_type(), 127);
	}

}
