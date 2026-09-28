//! Bounded local JSON-lines transport shared by desktop service clients.

use crate::ServiceRequest;
use std::io::{self, BufRead};

pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;

pub fn read_request(reader: &mut impl BufRead) -> io::Result<Option<ServiceRequest>> {
    let mut line = Vec::new();
    loop {
        let chunk = reader.fill_buf()?;
        let newline = chunk.iter().position(|byte| *byte == b'\n');
        let count = newline.unwrap_or(chunk.len());
        if count > MAX_REQUEST_BYTES - line.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "service request exceeds 1 MiB",
            ));
        }
        let eof = chunk.is_empty();
        line.extend_from_slice(&chunk[..count]);
        reader.consume(count + usize::from(newline.is_some()));
        if newline.is_some() || eof {
            if !line.iter().all(u8::is_ascii_whitespace) {
                return serde_json::from_slice(&line)
                    .map(Some)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error));
            }
            if eof {
                return Ok(None);
            }
            line.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const REQUEST: &str = r#"{"schemaVersion":"1","requestId":"read-1","operation":"applications.list","payload":{}}"#;

    #[test]
    fn rejects_oversized_valid_json_before_consuming_its_buffer() {
        let mut bytes = REQUEST.as_bytes().to_vec();
        bytes.resize(MAX_REQUEST_BYTES + 1, b' ');
        bytes.push(b'\n');
        let mut input = Cursor::new(bytes);
        let error = read_request(&mut input).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(input.position(), 0, "oversized fill_buf must not be copied or consumed");
    }

    #[test]
    fn accepts_bounded_messages_and_preserves_next_request() {
        let bytes = format!("\n{REQUEST}\r\n{REQUEST}");
        let mut input = Cursor::new(bytes);
        assert_eq!(read_request(&mut input).unwrap().unwrap().request_id, "read-1");
        assert_eq!(read_request(&mut input).unwrap().unwrap().request_id, "read-1");
        assert!(read_request(&mut input).unwrap().is_none());
    }

    #[test]
    fn rejects_unterminated_oversized_line_with_small_input_buffers() {
        let input = Cursor::new(vec![b' '; MAX_REQUEST_BYTES + 1]);
        let mut input = io::BufReader::with_capacity(37, input);
        assert_eq!(read_request(&mut input).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
}
