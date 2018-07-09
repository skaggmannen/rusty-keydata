extern crate clap;

mod keydata;

use clap::{App, Arg, SubCommand};

fn main() {
    let matches = App::new("key-data")
        .version("0.1")
        .about("read and write key data")
        .author("Fredrik Allansson")
        .subcommand(SubCommand::with_name("create")
            .about("creates key data")
        )
        .subcommand(SubCommand::with_name("read")
            .about("reads key data")
            .arg(Arg::with_name("INPUT")
                .required(true)
                .help("the key data to read")
            )
        )
        .get_matches();

    if let Some(_) = matches.subcommand_matches("create") {
        let key_data = keydata::singleblock::SingleBlock::new(0xaa_bb_cc_dd)
                                .with_valid_until(0x09_08_07_06)
                                .with_overriding_access(&[101], 1)
                                .with_non_overriding_access(&[1_000_000, 1_000_001])
                                .to_hex();
        println!("key_data: {}", &key_data);
        println!("size: {}", key_data.split_whitespace().count());
    } else if let Some(_) = matches.subcommand_matches("read") {

    }
}