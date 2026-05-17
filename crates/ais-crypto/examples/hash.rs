fn main() {
    let digest = ais_crypto::sha3_256(b"ais-core");
    for byte in digest {
        print!("{byte:02x}");
    }
    println!();
}
