#![feature(core)]
extern crate norx;
use std::str::from_utf8;
use norx::norx6441::{encrypt,decrypt};

pub fn main() {
    let k = [0u8; 32];
    let n = [0u8; 16];
    let m = "Hello, World!";
    let c = encrypt(&[], m.as_bytes(), &[], &n, &k);
    for x in c.iter() { 
        print!("{:02x} ", *x); 
    }
    println!("");
    match decrypt(&[], &c[..], &[], &n, &k) {
        Some(m) => println!("{}", from_utf8(&m[..]).unwrap()),
          None  => println!("bad ciphertext")
    }
    let mut c = c;
    c[0] ^= 1; // flip a bit
    match decrypt(&[], &c[..], &[], &n, &k) {
        Some(m) => println!("{}", from_utf8(&m[..]).unwrap()),
          None  => println!("bad ciphertext")
    }
}
 
