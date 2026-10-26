//! Manual AirPlay 2 AAC-LC playback probe.
//! Run with `cargo run -p raop --example aac_tone -- 192.168.1.10:7000`.

#[cfg(any(target_os = "macos", windows))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use raop::ap2::session::{Ap2AudioCodec, Ap2Config, Ap2Session, SAMPLES_PER_PACKET};
    use std::f32::consts::TAU;
    use std::net::SocketAddr;
    use std::time::Duration;

    let target: SocketAddr = std::env::args()
        .nth(1)
        .ok_or("pass the speaker IP:port")?
        .parse()?;
    let mut frame = 0u64;
    let cfg = Ap2Config {
        target,
        codec: Ap2AudioCodec::AacLc,
        volume_db: -12.0,
        quiet_mode: false,
        initial_progress: true,
        ..Default::default()
    };
    let session = Ap2Session::start(cfg, move |pcm: &mut [i16; SAMPLES_PER_PACKET]| {
        for stereo in pcm.chunks_exact_mut(2) {
            let phase = frame as f32 * 440.0 * TAU / 44_100.0;
            let sample = (phase.sin() * 7_000.0) as i16;
            stereo[0] = sample;
            stereo[1] = sample;
            frame += 1;
        }
    })
    .await?;
    tokio::time::sleep(Duration::from_secs(15)).await;
    session.stop().await;
    Ok(())
}

#[cfg(not(any(target_os = "macos", windows)))]
fn main() {
    eprintln!("The native AAC-LC encoder is available on macOS and Windows.");
}
