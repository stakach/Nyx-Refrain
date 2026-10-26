//! Uncompressed stereo ALAC frames for AirPlay receivers that do not play raw PCM.
//!
//! The 23-bit frame header is stereo (001), 19 reserved zero bits, and the
//! uncompressed flag (1). PCM samples follow in big-endian order, then the
//! three-bit end tag (111). This is the framing used by pyatv before it
//! switched to raw PCM streams.

pub const PCM_SAMPLES: usize = 352 * 2;
pub const FRAME_BYTES: usize = (23 + PCM_SAMPLES * 16 + 3).div_ceil(8);

pub fn encode_uncompressed(pcm: &[i16; PCM_SAMPLES], out: &mut [u8; FRAME_BYTES]) {
    out.fill(0);
    // 001, nineteen zero bits, then 1.
    out[0] = 0x20;
    out[2] = 0x02;
    // The samples begin at bit 23, so each 16-bit sample straddles three bytes.
    for (index, sample) in pcm.iter().enumerate() {
        let value = *sample as u16;
        let byte = (23 + index * 16) / 8;
        out[byte] |= (value >> 15) as u8;
        out[byte + 1] = (value >> 7) as u8;
        out[byte + 2] = (value << 1) as u8;
    }
    // End tag starts at bit 23 + 704 * 16, also at offset 7 within a byte.
    out[FRAME_BYTES - 2] |= 1;
    out[FRAME_BYTES - 1] = 0xC0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_header_samples_and_end_tag() {
        let mut pcm = [0; PCM_SAMPLES];
        pcm[0] = 0x1234;
        pcm[1] = -2;
        pcm[PCM_SAMPLES - 1] = 0x5678;
        let mut frame = [0; FRAME_BYTES];
        encode_uncompressed(&pcm, &mut frame);
        assert_eq!(FRAME_BYTES, 1412);
        assert_eq!(&frame[..7], &[0x20, 0x00, 0x02, 0x24, 0x69, 0xff, 0xfc]);
        assert_eq!(frame[FRAME_BYTES - 2] & 1, 1);
        assert_eq!(frame[FRAME_BYTES - 1], 0xC0);
        for (index, expected) in pcm.iter().enumerate() {
            let bit = 23 + index * 16;
            let byte = bit / 8;
            let decoded = ((frame[byte] as u16 & 1) << 15)
                | ((frame[byte + 1] as u16) << 7)
                | ((frame[byte + 2] as u16) >> 1);
            assert_eq!(decoded as i16, *expected);
        }
    }
}
