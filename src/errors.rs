use clap;
use serial;
use std;

error_chain! {
    foreign_links {

        OptionError(clap::Error);
        UartError(serial::Error);
        IOError(std::io::Error);
    }

    errors {
        InvalidPacketData(reason: String) {
            description("invalid packet data")
            display("invalid packet data: {}", reason)
        }
    }

}
