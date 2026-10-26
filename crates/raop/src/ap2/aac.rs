//! AAC-LC access units for AirPlay 2 buffered audio (type 103).
//!
//! AudioToolbox and Media Foundation supply the platform encoder. This module
//! deliberately does not select AAC for realtime (type 96) streams: an AAC
//! access unit needs the buffered transport and its separate timing protocol.

use zvidlib_aac_encoder::native_aac_audio_encoder_factory;
use zvidlib_core::{
    AudioBuffer, AudioEncoder, AudioEncoderConfig, AudioEncoderFactory, Codec, CodecProfile,
    EncodedSample, FrameIndex, Limits, SampleRange,
};

pub const FRAMES_PER_ACCESS_UNIT: usize = 1024;
pub const CHANNELS: usize = 2;
pub const SAMPLE_RATE: u32 = 44_100;
pub const BIT_RATE: u32 = 128_000;
pub const AUDIO_FORMAT: u64 = 0x400000;
pub const COMPRESSION_TYPE: u64 = 4;
pub const STREAM_TYPE: u8 = 103;

/// MPEG-4 AudioSpecificConfig: AAC-LC, 44.1 kHz, stereo.
pub const AUDIO_SPECIFIC_CONFIG: [u8; 2] = [0x12, 0x10];

pub struct AacLcEncoder {
    inner: Box<dyn AudioEncoder>,
    input_frames: u64,
    input_index: u64,
    limits: Limits,
}

impl AacLcEncoder {
    pub fn new() -> Result<Self, String> {
        let limits = Limits::default();
        let config = AudioEncoderConfig {
            codec: Codec::Aac,
            profile: CodecProfile::AacLowComplexity,
            sample_rate: SAMPLE_RATE,
            channels: CHANNELS as u16,
            timescale: SAMPLE_RATE,
            configuration: BIT_RATE.to_be_bytes().to_vec(),
        };
        let inner = native_aac_audio_encoder_factory()
            .create(&config, &limits)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            inner,
            input_frames: 0,
            input_index: 0,
            limits,
        })
    }

    /// Feed one 1024-frame interleaved PCM block. Platform encoders may hold
    /// initial frames for look-ahead and return zero or several access units.
    pub fn encode(
        &mut self,
        pcm: &[i16; FRAMES_PER_ACCESS_UNIT * CHANNELS],
    ) -> Result<Vec<EncodedSample>, String> {
        let samples = pcm.iter().map(|sample| *sample as f32 / 32768.0).collect();
        let end = self.input_frames + FRAMES_PER_ACCESS_UNIT as u64;
        let range = SampleRange::new(self.input_frames, end).map_err(|error| error.to_string())?;
        let buffer = AudioBuffer::new(range, SAMPLE_RATE, CHANNELS as u16, samples, &self.limits)
            .map_err(|error| error.to_string())?;
        let encoded = pollster::block_on(self.inner.encode(FrameIndex(self.input_index), buffer))
            .map_err(|error| error.to_string())?;
        self.input_frames = end;
        self.input_index += 1;
        Ok(encoded)
    }

    pub fn finish(&mut self) -> Result<Vec<EncodedSample>, String> {
        Ok(pollster::block_on(self.inner.finish())
            .map_err(|error| error.to_string())?
            .samples)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_encoder_emits_raw_aac_access_units() {
        let mut encoder = AacLcEncoder::new().expect("native AAC-LC encoder");
        let mut packets = Vec::new();
        for block in 0..50 {
            let mut pcm = [0i16; FRAMES_PER_ACCESS_UNIT * CHANNELS];
            for frame in 0..FRAMES_PER_ACCESS_UNIT {
                let phase =
                    (block * FRAMES_PER_ACCESS_UNIT + frame) as f32 * 440.0 * std::f32::consts::TAU
                        / SAMPLE_RATE as f32;
                let sample = (phase.sin() * 8000.0) as i16;
                pcm[frame * 2] = sample;
                pcm[frame * 2 + 1] = sample;
            }
            packets.extend(encoder.encode(&pcm).expect("encode AAC block"));
        }
        packets.extend(encoder.finish().expect("drain AAC encoder"));
        assert!(packets.len() >= 50, "lost access units: {}", packets.len());
        assert!(packets.iter().all(|packet| !packet.data.is_empty()));
        assert!(packets.iter().all(|packet| packet.duration == 1024));
        assert!(packets.iter().all(|packet| packet.data.len() < 4096));
        assert_eq!(AUDIO_SPECIFIC_CONFIG, [0x12, 0x10]);
    }
}
