use anyhow::{Context, Result};
use clap::Parser;
use galileo_osnma::{
    galmon::{navmon::nav_mon_message::GalileoInav, transport::ReadTransport},
    storage::FullStorage,
    types::{BitSlice, NUM_SVNS},
    Gst, InavBand, Osnma, PublicKey, Svn, Validated, Wn,
};
use spki::DecodePublicKey;
use std::{collections::HashMap, io::Read};

/// Process OSNMA data reading Galmon protobuf from stdin
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Merkle tree root in hex.
    #[arg(long)]
    merkle_root: Option<String>,
    /// Path to the P-256 public key in PEM format.
    #[arg(long)]
    pubkey: Option<String>,
    /// P-521 public key in hexadecimal format (SEC1 encoding).
    #[arg(long)]
    pubkey_p521: Option<String>,
    /// ID of the public key.
    #[arg(long)]
    pkid: Option<u8>,
    /// Only process slow MAC data.
    #[arg(long)]
    slow_mac_only: bool,
}

fn load_pubkey(path: &str, pkid: u8) -> Result<PublicKey<Validated>> {
    let mut file = std::fs::File::open(path)?;
    let mut pem = String::new();
    file.read_to_string(&mut pem)?;
    let pubkey = p256::ecdsa::VerifyingKey::from_public_key_pem(&pem)?;
    Ok(PublicKey::from_p256(pubkey, pkid).force_valid())
}

fn load_pubkey_p521(hex: &str, pkid: u8) -> Result<PublicKey<Validated>> {
    let pubkey = hex::decode(hex)?;
    let pubkey = p521::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey)?;
    Ok(PublicKey::from_p521(pubkey, pkid).force_valid())
}
//add function for display CED and status data------------

fn extract_bits_range(data_bytes: &[u8], start: usize, end: usize) -> u32 {
    let mut value: u32 = 0;
    for i in start..=end {
        let byte_index = i / 8;
        let bit_index = i % 8;
        let bit = (data_bytes[byte_index] >> (7 - bit_index)) & 1;
        value = (value << 1) | bit as u32;
    }
    value
}
fn extract_all_bits(data_bytes: &[u8]) -> HashMap<&'static str, u32> {
    let mut map = HashMap::new();
    map.insert("T0E", extract_bits_range(data_bytes, 11, 24));
    map.insert("M0", extract_bits_range(data_bytes, 25, 56));
    map.insert("E", extract_bits_range(data_bytes, 57, 88));
    map.insert("AQRTA", extract_bits_range(data_bytes, 89, 120));
    map.insert("OMEGA0", extract_bits_range(data_bytes, 131, 162));
    map.insert("I0", extract_bits_range(data_bytes, 163, 194));
    map.insert("OMEGA", extract_bits_range(data_bytes, 195, 226));
    map.insert("IDOT", extract_bits_range(data_bytes, 227, 240));
    map.insert("OMEGADOT", extract_bits_range(data_bytes, 251, 274));
    map.insert("DELTAN", extract_bits_range(data_bytes, 275, 290));
    map.insert("CUC", extract_bits_range(data_bytes, 291, 306));
    map.insert("CUS", extract_bits_range(data_bytes, 307, 322));
    map.insert("CRC", extract_bits_range(data_bytes, 323, 338));
    map.insert("CRS", extract_bits_range(data_bytes, 339, 354));
    map.insert("CIC", extract_bits_range(data_bytes, 379, 394));
    map.insert("CIS", extract_bits_range(data_bytes, 395, 410));
    map.insert("T0C", extract_bits_range(data_bytes, 411, 424));
    map.insert("AF0", extract_bits_range(data_bytes, 425, 455));
    map.insert("AF1", extract_bits_range(data_bytes, 456, 476));
    map.insert("AF2", extract_bits_range(data_bytes, 477, 482));
    map.insert("AI0", extract_bits_range(data_bytes, 483, 493));
    map.insert("AI1", extract_bits_range(data_bytes, 494, 504));
    map.insert("AI2", extract_bits_range(data_bytes, 505, 518));
    map.insert("REGION1", extract_bits_range(data_bytes, 519, 519));
    map.insert("REGION2", extract_bits_range(data_bytes, 520, 520));
    map.insert("REGION3", extract_bits_range(data_bytes, 521, 521));
    map.insert("REGION4", extract_bits_range(data_bytes, 522, 522));
    map.insert("REGION5", extract_bits_range(data_bytes, 523, 523));
    map.insert("BGDA", extract_bits_range(data_bytes, 524, 533));
    map.insert("BGDB", extract_bits_range(data_bytes, 534, 543));
    map.insert("E5BHS", extract_bits_range(data_bytes, 544, 545));
    map.insert("E1BHS", extract_bits_range(data_bytes, 546, 547));
    map.insert("E5BDVS", extract_bits_range(data_bytes, 548, 548));
    map.insert("E1BDVS", extract_bits_range(data_bytes, 549, 549));
    map
}

fn hashmap_to_string(map: &HashMap<&str, u32>) -> String {
    map.iter()
        .map(|(key, value)| format!("{}: {}", key, value))
        .collect::<Vec<String>>()
        .join(", ")
}

/* 

macro_rules! ced_and_status_range {
    ($($name:ident, $start:expr, $end:expr);* $(;)?) => {
        $(
            const $name: (usize, usize) = ($start, $end);
        )*
    };
}
ced_and_status_range!(
    T0E, 11, 24;
    M0, 25, 56;
    E, 57, 88;
    AQRTA,89,120;

    OMEGA0,131,162;
    I0,163,194;
    OMEGA,195,226;
    IDOT,227,240;

    OMEGADOT,251,274;
    DELTAN,275,290;
    CUC,291,306;
    CUS,307,322;
    CRC,323,338;
    CRS,339,354;

    CIC,379,394;
    CIS,395,410; 
    T0C,411,424;
    AF0,425,455;
    AF1,456,476;
    AF2,477,482;

    AI0,483,493;
    AI1,494,504;
    AI2,505,518;
    REGION1,519,519;
    REGION2,520,520;
    REGION3,521,521;
    REGION4,522,522;
    REGION5,523,523;
    BGDA,524,533;
    BGDB,534,543;
    E5BHS,544,545;
    E1BHS,546,547;
    E5BDVS,548,548;
    E1BDVS,549,549;
);
*/
//---------------------------------------------------------
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    if args.merkle_root.is_none() && args.pubkey.is_none() && args.pubkey_p521.is_none() {
        anyhow::bail!("at least either the Merkle tree root or the public key must be specified");
    }

    if args.pubkey.is_some() && args.pubkey_p521.is_some() {
        anyhow::bail!("the --pubkey and --pubkey-p521 arguments are mutually exclusive");
    }

    if args.pubkey.is_some() && args.pkid.is_none() {
        anyhow::bail!("the --pubkey and --pkid arguments need to be both specified together");
    }

    if args.pubkey_p521.is_some() && args.pkid.is_none() {
        anyhow::bail!("the --pubkey-p521 and --pkid arguments need to be both specified together");
    }

    if args.pkid.is_some() && args.pubkey.is_none() && args.pubkey_p521.is_none() {
        anyhow::bail!(
            "the --pkid argument needs to be used together with --pubkey or --pubkey-p521"
        );
    }

    let pubkey = if let Some(pubkey_path) = &args.pubkey {
        Some(load_pubkey(pubkey_path, args.pkid.unwrap())?)
    } else if let Some(pubkey_hex) = &args.pubkey_p521 {
        Some(load_pubkey_p521(pubkey_hex, args.pkid.unwrap())?)
    } else {
        None
    };

    let mut osnma: Osnma<FullStorage> = if let Some(merkle) = &args.merkle_root {
        let merkle = hex::decode(merkle)
            .context("failed to parse Merkle tree root")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("the Merkle tree root has a wrong length"))?;
        Osnma::from_merkle_tree(merkle, pubkey, args.slow_mac_only)
    } else {
        // Here pubkey shouldn't be None, because Merkle tree is None and we
        // have checked that at least one of both is not None.
        Osnma::from_pubkey(pubkey.unwrap(), args.slow_mac_only)
    };

    let mut read = ReadTransport::new(std::io::stdin());
    let mut timing_parameters: [Option<[u8; 18]>; NUM_SVNS] = [None; NUM_SVNS];
    let mut ced_and_status_data: [Option<[u8; 69]>; NUM_SVNS] = [None; NUM_SVNS];
    let mut current_subframe = None;
    let mut last_tow_mod_30 = 0;

    while let Some(packet) = read.read_packet()? {
        if let Some(
            inav @ GalileoInav {
                contents: inav_word,
                reserved1: osnma_data,
                sigid: Some(sigid),
                ..
            },
        ) = &packet.gi
        {
            // This is needed because sometimes we can see a TOW of 604801
            let secs_in_week = 604800;
            let mut tow = inav.gnss_tow % secs_in_week;
            let wn = Wn::try_from(inav.gnss_wn).unwrap()
                + Wn::try_from(inav.gnss_tow / secs_in_week).unwrap();

            // Fix bug in Galmon data:
            //
            // Often, the E1B word 16 starting at TOW = 29 mod 30 will have the
            // TOW of the previous word 16 in the subframe, which starts at TOW
            // = 15 mod 30. We detect this condition by looking at the last tow
            // mod 30 that we saw and fixing if needed.
            if tow % 30 == 15 && last_tow_mod_30 >= 19 {
                log::debug!(
                    "fixing wrong TOW for SVN {}; tow = {}, last tow mod 30 = {}",
                    inav.gnss_sv,
                    tow,
                    last_tow_mod_30
                );
                tow += 29 - 15; // wn rollover is not possible by this addition
            }
            last_tow_mod_30 = tow % 30;

            let gst = Gst::new(wn, tow);
            if let Some(current) = current_subframe {
                if current > gst.gst_subframe() {
                    // Avoid processing INAV words that are in a previous subframe
                    log::warn!(
                        "dropping INAV word from previous subframe (current subframe {:?}, \
			 this INAV word {:?} SVN {} band {})",
                        current,
                        gst,
                        inav.gnss_sv,
                        sigid
                    );
                    continue;
                }
            }
            current_subframe = Some(gst.gst_subframe());
            let svn = Svn::try_from(inav.gnss_sv).unwrap();
            let band = match sigid {
                1 => InavBand::E1B,
                5 => InavBand::E5B,
                _ => {
                    log::error!("INAV word received on non-INAV band: sigid = {}", sigid);
                    continue;
                }
            };

            // The OSNMA SIS ICD says that OSNMA is not provided in INAV Dummy
            // Messages or Alert Pages. The OSNMA field in these pages may not
            // contain all zeros, but is invalid and should be discarded.
            //
            // Here we drop INAV words that are Dummy Messages. There is no way
            // for us to filter for Alert Pages in Galmon data (the page type
            // bit is not present), so hopefully these pages don't make it here.
            let inav_word_type = inav_word[0] >> 2;
            if inav_word_type == 63 {
                log::debug!(
                    "discarding dummy INAV word from {} {:?} at {:?}",
                    svn,
                    band,
                    gst
                );
                continue;
            }

            osnma.feed_inav(inav_word[..].try_into().unwrap(), svn, gst, band);
            if let Some(osnma_data) = osnma_data {
                osnma.feed_osnma(osnma_data[..].try_into().unwrap(), svn, gst);
            }

            for svn in Svn::iter() {
                let idx = usize::from(svn) - 1;
                if let Some(data) = osnma.get_ced_and_status(svn) {
                    let mut data_bytes = [0u8; 69];
                    let a = BitSlice::from_slice_mut(&mut data_bytes);
                    let b = data.data();
                    a[..b.len()].copy_from_bitslice(b);
                    if !ced_and_status_data[idx]
                        .map(|d| d == data_bytes)
                        .unwrap_or(false)
                    {
                        //Extract CED and STATUS data from the data bytes----------------
                        let extracted_bits = extract_all_bits(&data_bytes);
                        let extracted_bits_str = hashmap_to_string(&extracted_bits);
                        //-----------------------------------------------------------------
                        
                        log::info!(
                            "new CED and status for {} authenticated \
                                    (authbits = {}, GST = {:?},data = {{{}}})",
                            svn,
                            data.authbits(),
                            data.gst(),
                            extracted_bits_str
                        );
                        ced_and_status_data[idx] = Some(data_bytes);
                    }
                }
                if let Some(data) = osnma.get_timing_parameters(svn) {
                    let mut data_bytes = [0u8; 18];
                    let a = BitSlice::from_slice_mut(&mut data_bytes);
                    let b = data.data();
                    a[..b.len()].copy_from_bitslice(b);
                    if !timing_parameters[idx]
                        .map(|d| d == data_bytes)
                        .unwrap_or(false)
                    {
                        log::info!(
                            "new timing parameters for {} authenticated (authbits = {}, GST = {:?})",
			    svn,
                            data.authbits(),
                            data.gst()
			);
                        timing_parameters[idx] = Some(data_bytes);
                    }
                }
            }
        }
    }

    Ok(())
}
