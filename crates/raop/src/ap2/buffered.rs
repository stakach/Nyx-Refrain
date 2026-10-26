//! AirPlay 2 type-103 TCP audio frame construction.
//!
//! The two-byte big-endian prefix counts itself. It precedes a normal RTP
//! header, encrypted AAC-LC access unit, Poly1305 tag, and eight-byte nonce.

use super::audio::{AUDIO_TRAILER_LEN, AudioCipher};

pub const PAYLOAD_TYPE: u8 = 103;
const RTP_HEADER_LEN: usize = 12;
const FRAME_PREFIX_LEN: usize = 2;

/// Build one length-prefixed encrypted RTP frame for a buffered data socket.
pub fn seal_audio_frame(
    cipher: &mut AudioCipher,
    first: bool,
    sequence: u16,
    timestamp: u32,
    ssrc: u32,
    access_unit: &[u8],
) -> Result<Vec<u8>, String> {
    let total = FRAME_PREFIX_LEN + RTP_HEADER_LEN + access_unit.len() + AUDIO_TRAILER_LEN;
    let length =
        u16::try_from(total).map_err(|_| "AAC access unit exceeds TCP frame".to_owned())?;
    let mut header = [0u8; RTP_HEADER_LEN];
    header[0] = 0x80;
    header[1] = PAYLOAD_TYPE | if first { 0x80 } else { 0 };
    header[2..4].copy_from_slice(&sequence.to_be_bytes());
    header[4..8].copy_from_slice(&timestamp.to_be_bytes());
    header[8..12].copy_from_slice(&ssrc.to_be_bytes());
    let mut frame = vec![0u8; total];
    frame[..2].copy_from_slice(&length.to_be_bytes());
    let written = cipher.seal(&header, access_unit, &mut frame[2..]);
    debug_assert_eq!(written + FRAME_PREFIX_LEN, total);
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};

    #[test]
    fn buffered_frame_has_length_rtp_aac_and_nonce() {
        let key = [7u8; 32];
        let mut cipher = AudioCipher::new(&key);
        for (first, seq, counter) in [(true, 0x1234, 0u64), (false, 0x1235, 1)] {
            let frame = seal_audio_frame(
                &mut cipher,
                first,
                seq,
                0x1234_5678,
                0xaabb_ccdd,
                b"AAC access unit",
            )
            .unwrap();
            assert_eq!(
                u16::from_be_bytes([frame[0], frame[1]]) as usize,
                frame.len()
            );
            assert_eq!(frame[2], 0x80);
            assert_eq!(frame[3], if first { 0xe7 } else { 0x67 });
            assert_eq!(&frame[4..6], &seq.to_be_bytes());
            assert_eq!(&frame[6..10], &0x1234_5678u32.to_be_bytes());
            assert_eq!(&frame[10..14], &0xaabb_ccddu32.to_be_bytes());
            assert_eq!(&frame[frame.len() - 8..], &counter.to_le_bytes());

            let body_end = frame.len() - AUDIO_TRAILER_LEN;
            let mut plain = frame[14..body_end].to_vec();
            let mut nonce = [0u8; 12];
            nonce[4..].copy_from_slice(&frame[frame.len() - 8..]);
            ChaCha20Poly1305::new(Key::from_slice(&key))
                .decrypt_in_place_detached(
                    Nonce::from_slice(&nonce),
                    &frame[6..14],
                    &mut plain,
                    Tag::from_slice(&frame[body_end..body_end + 16]),
                )
                .unwrap();
            assert_eq!(&plain, b"AAC access unit");
        }
    }

    #[test]
    fn buffered_frame_rejects_oversized_access_unit() {
        let mut cipher = AudioCipher::new(&[0u8; 32]);
        assert!(seal_audio_frame(&mut cipher, true, 0, 0, 0, &[0; 65_500]).is_err());
    }
}
