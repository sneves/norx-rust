
extern crate norx;
use std::str::from_utf8;
use norx::norx6441::{encrypt,decrypt};

pub fn main() {
    let k = [0u8, ..32];
    let n = [0u8, ..16];
    let m = "Hello, World!";
    let c = encrypt([], m.as_bytes(), [], n, k);
    for x in c.iter() { 
        print!("{:02x} ", *x); 
    }
    println!("");
    match decrypt([], c.as_slice(), [], n, k) {
        Some(m) => println!("{}", from_utf8(m.as_slice()).expect("bad utf-8")),
          None  => println!("bad ciphertext")
    }
    let mut c = c;
    *c.get_mut(0) ^= 1; // flip a bit
    match decrypt([], c.as_slice(), [], n, k) {
        Some(m) => println!("{}", from_utf8(m.as_slice()).expect("bad utf-8")),
          None  => println!("bad ciphertext")
    }
}
 
