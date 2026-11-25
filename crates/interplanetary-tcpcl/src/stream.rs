//! Virtual ordered byte stream for TCPCL testing
//!
//! Simulates a reliable ordered byte stream without actual TCP sockets.
//! Allows arbitrary chunking to test message framing robustness.

use std::collections::VecDeque;

/// TCP connection close mechanism per RFC 9174 §4.1-014
///
/// RFC 9174 §4.1-014: "When an entity is said to 'close' a TCP connection
/// the entity SHALL use the TCP FIN mechanism and not the RST mechanism."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseKind {
    /// Graceful close with TCP FIN (required by RFC 9174 §4.1-014)
    Fin,
    /// Abrupt close with TCP RST (should not be used by TCPCL)
    Rst,
}

/// Virtual ordered byte stream (no real TCP).
///
/// Buffers bytes written by one side and makes them available for reading
/// by the other side. Supports arbitrary chunking to test TCPCL message
/// framing under various network conditions.
///
/// # Examples
///
/// ```
/// use interplanetary_tcpcl::VirtualStream;
///
/// let mut stream = VirtualStream::new();
/// stream.write(b"SESS_INIT").unwrap();
///
/// let mut buf = [0u8; 4];
/// assert_eq!(stream.read(&mut buf).unwrap(), 4);
/// assert_eq!(&buf, b"SESS");
///
/// let mut rest = [0u8; 8];
/// assert_eq!(stream.read(&mut rest).unwrap(), 5);
/// assert_eq!(&rest[..5], b"_INIT");
/// ```
#[derive(Debug, Clone)]
pub struct VirtualStream {
    /// Buffered bytes waiting to be read
    buffer: VecDeque<u8>,
    /// Whether the stream has been closed and how
    close_state: Option<CloseKind>,
}

impl VirtualStream {
    /// Create new empty stream
    pub fn new() -> Self {
        Self {
            buffer: VecDeque::new(),
            close_state: None,
        }
    }

    /// Write bytes to stream
    pub fn write(&mut self, data: &[u8]) -> Result<usize, std::io::Error> {
        if self.close_state.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Stream closed",
            ));
        }

        self.buffer.extend(data);
        Ok(data.len())
    }

    /// Read up to `buf.len()` bytes from stream
    ///
    /// Returns number of bytes read (may be less than requested).
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        let available = self.buffer.len().min(buf.len());

        for item in buf.iter_mut().take(available) {
            *item = self.buffer.pop_front().unwrap();
        }

        Ok(available)
    }

    /// Read exact number of bytes (blocks until available)
    ///
    /// For testing: simulates blocking read. In real async code,
    /// this would be `async fn` with `.await`.
    pub fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), std::io::Error> {
        if buf.len() > self.buffer.len() && self.close_state.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Stream closed before all data available",
            ));
        }

        for byte in buf.iter_mut() {
            *byte = self.buffer.pop_front().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::WouldBlock, "Not enough data")
            })?;
        }

        Ok(())
    }

    /// Peek at available bytes without consuming
    pub fn peek(&self, count: usize) -> &[u8] {
        let _available = count.min(self.buffer.len());
        // VecDeque doesn't expose slices easily, so this is a simplification
        // In real code, use two contiguous slices
        &[] // Simplified for now
    }

    /// Number of bytes available to read
    pub fn available(&self) -> usize {
        self.buffer.len()
    }

    /// Close the stream with FIN (graceful close per RFC 9174 §4.1-014)
    ///
    /// RFC 9174 §4.1-014: "When an entity is said to 'close' a TCP connection
    /// the entity SHALL use the TCP FIN mechanism and not the RST mechanism."
    pub fn close(&mut self) {
        self.close_with(CloseKind::Fin);
    }

    /// Close the stream with specified mechanism
    ///
    /// RFC 9174 §4.1-014: SDK-initiated closes MUST use CloseKind::Fin
    pub fn close_with(&mut self, kind: CloseKind) {
        self.close_state = Some(kind);
    }

    /// Check if stream is closed
    pub fn is_closed(&self) -> bool {
        self.close_state.is_some()
    }

    /// Get the close kind if stream is closed
    ///
    /// RFC 9174 §4.1-014: Returns Some(CloseKind::Fin) for graceful SDK closes,
    /// Some(CloseKind::Rst) for abrupt closes (which should not occur in SDK code)
    pub fn close_kind(&self) -> Option<CloseKind> {
        self.close_state
    }
}

impl Default for VirtualStream {
    fn default() -> Self {
        Self::new()
    }
}

/// Bidirectional virtual stream pair for TCPCL peers.
///
/// Writes on one side appear as reads on the other — useful for framing tests
/// without sockets.
///
/// # Examples
///
/// ```
/// use interplanetary_tcpcl::StreamPair;
///
/// let mut pair = StreamPair::new();
/// pair.write_local(b"hello").unwrap();
///
/// let mut buf = [0u8; 5];
/// assert_eq!(pair.read_remote(&mut buf).unwrap(), 5);
/// assert_eq!(&buf, b"hello");
///
/// pair.write_remote(b"ack").unwrap();
/// let mut ack = [0u8; 3];
/// assert_eq!(pair.read_local(&mut ack).unwrap(), 3);
/// assert_eq!(&ack, b"ack");
/// ```
#[derive(Debug)]
pub struct StreamPair {
    /// Local → remote direction stream
    pub local_to_remote: VirtualStream,
    /// Remote → local direction stream
    pub remote_to_local: VirtualStream,
}

impl StreamPair {
    /// Create new stream pair
    pub fn new() -> Self {
        Self {
            local_to_remote: VirtualStream::new(),
            remote_to_local: VirtualStream::new(),
        }
    }

    /// Write from local to remote
    pub fn write_local(&mut self, data: &[u8]) -> Result<usize, std::io::Error> {
        self.local_to_remote.write(data)
    }

    /// Read at remote from local's writes
    pub fn read_remote(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        self.local_to_remote.read(buf)
    }

    /// Write from remote to local
    pub fn write_remote(&mut self, data: &[u8]) -> Result<usize, std::io::Error> {
        self.remote_to_local.write(data)
    }

    /// Read at local from remote's writes
    pub fn read_local(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        self.remote_to_local.read(buf)
    }

    /// Close local side with FIN (graceful per RFC 9174 §4.1-014)
    pub fn close_local(&mut self) {
        self.local_to_remote.close();
    }

    /// Close remote side with FIN (graceful per RFC 9174 §4.1-014)
    pub fn close_remote(&mut self) {
        self.remote_to_local.close();
    }

    /// Close local side with specified mechanism
    pub fn close_local_with(&mut self, kind: CloseKind) {
        self.local_to_remote.close_with(kind);
    }

    /// Close remote side with specified mechanism
    pub fn close_remote_with(&mut self, kind: CloseKind) {
        self.remote_to_local.close_with(kind);
    }
}

impl Default for StreamPair {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtual_stream_write_read() {
        let mut stream = VirtualStream::new();

        // Write some data
        let written = stream.write(b"hello").unwrap();
        assert_eq!(written, 5);
        assert_eq!(stream.available(), 5);

        // Read it back
        let mut buf = [0u8; 10];
        let read = stream.read(&mut buf).unwrap();
        assert_eq!(read, 5);
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(stream.available(), 0);
    }

    #[test]
    fn test_virtual_stream_chunking() {
        let mut stream = VirtualStream::new();

        // Write in chunks
        stream.write(b"hello ").unwrap();
        stream.write(b"world").unwrap();
        assert_eq!(stream.available(), 11);

        // Read in different chunks
        let mut buf = [0u8; 3];
        assert_eq!(stream.read(&mut buf).unwrap(), 3);
        assert_eq!(&buf, b"hel");

        let mut buf = [0u8; 10];
        assert_eq!(stream.read(&mut buf).unwrap(), 8);
        assert_eq!(&buf[..8], b"lo world");
    }

    #[test]
    fn test_stream_pair_bidirectional() {
        let mut pair = StreamPair::new();

        // Local writes
        pair.write_local(b"ping").unwrap();

        // Remote reads
        let mut buf = [0u8; 10];
        let n = pair.read_remote(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ping");

        // Remote writes
        pair.write_remote(b"pong").unwrap();

        // Local reads
        let n = pair.read_local(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"pong");
    }

    #[test]
    fn test_stream_close() {
        let mut stream = VirtualStream::new();

        stream.write(b"data").unwrap();
        stream.close();

        // Can still read buffered data
        let mut buf = [0u8; 10];
        assert_eq!(stream.read(&mut buf).unwrap(), 4);

        // But can't write more
        assert!(stream.write(b"more").is_err());
    }
}
