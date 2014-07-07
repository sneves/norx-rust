#![macro_escape]

use std::num::{Zero,One,cast};
use std::slice::bytes::copy_memory;
use std::mem::size_of;

static NORX_B : uint = 16; // total words
static NORX_C : uint =  6; // capacity words
static NORX_K : uint =  4; // key words
static NORX_N : uint =  2; // nonce words
static NORX_R : uint = NORX_B - NORX_C; // rate words
static NORX_A : uint = NORX_R; // maximum tag size

// XXX: hack; Rust could really use compile-time sizeof(T)
static MAX_RATE_BYTES : uint = 64 * NORX_R / 8; 

#[inline]
fn load_le<T : Int + NumCast>(v : &[u8]) -> T {
	let n = size_of::<T>();
	let mut x : T = Zero::zero();
	for i in range(0, n) {
        let b: T = cast(v[i]).unwrap();
		x = x | (b << cast(i*8).unwrap());
	}
	return x;
}

#[inline]
fn store_le<T : Int + NumCast>(v: &mut [u8], mut x: T) {
    let n = size_of::<T>();
    for i in range(0, n) {
        v[i] = cast(x & cast(0xFFu8).unwrap()).unwrap();
        x = x >> cast(8u8).unwrap();
    }
}

#[inline]
fn bytes<T>() -> uint {
	size_of::<T>()	
}

#[inline]
fn bits<T>() -> uint {
	bytes::<T>() * 8
}

#[inline]
fn rate_bytes<T>() -> uint {
	bytes::<T>() * NORX_R
}

#[inline]
fn key_bytes<T>() -> uint {
	bytes::<T>() * NORX_K
}

#[inline]
fn nonce_bytes<T>() -> uint {
	bytes::<T>() * NORX_N
}

#[inline]
fn rotations<T: Int>() -> Option<[uint, ..4]> {
	match bits::<T>() {
		32 => Some([ 8, 11, 16, 31]),
		64 => Some([ 8, 19, 40, 63]),
		 _ => None // This should really be a compile-time failure
	}
}

fn constants<T : NumCast>() -> Option<(T, T, T, T)> {
	match bits::<T>() { // Poor man's template specialization
		32 => Some((cast(0x243F6A88u32).unwrap(), 
                    cast(0x85A308D3u32).unwrap(), 
                    cast(0x13198A2Eu32).unwrap(), 
                    cast(0x03707344u32).unwrap())),
		64 => Some((cast(0x243F6A8885A308D3u64).unwrap(), 
                    cast(0x13198A2E03707344u64).unwrap(), 
                    cast(0xA4093822299F31D0u64).unwrap(), 
                    cast(0x082EFA98EC4E6C89u64).unwrap())),
		 _ => None 
	}
}

#[inline]
#[allow(non_snake_case_functions)]
fn U<T: Int>(x: T, y: T) -> T {
	x ^ y ^ ((x & y) << One::one())
}

#[inline]
#[allow(non_snake_case_functions)]
fn G<T : Int>(mut a: T, mut b: T, mut c: T, mut d: T) -> (T, T, T, T) {
	let r = rotations::<T>().unwrap();
	a = U(a, b); d = d ^ a; d = d.rotate_right(r[0]);
	c = U(c, d); b = b ^ c; b = b.rotate_right(r[1]);
	a = U(a, b); d = d ^ a; d = d.rotate_right(r[2]);
	c = U(c, d); b = b ^ c; b = b.rotate_right(r[3]);
	return (a, b, c, d);
}

#[allow(non_snake_case_functions)]
fn F<T: Int>(x : &mut [T, ..NORX_B]) {
	macro_rules!G(
		($a: expr, $b: expr, $c: expr, $d: expr) => 
		({
			let r = rotations::<T>().unwrap();
			$a = U($a, $b); $d = $d ^ $a; $d = $d.rotate_right(r[0]);
			$c = U($c, $d); $b = $b ^ $c; $b = $b.rotate_right(r[1]);
			$a = U($a, $b); $d = $d ^ $a; $d = $d.rotate_right(r[2]);
			$c = U($c, $d); $b = $b ^ $c; $b = $b.rotate_right(r[3]);
		})
	)

	// Column step
	G!(x[ 0], x[ 4], x[ 8], x[12]);
	G!(x[ 1], x[ 5], x[ 9], x[13]);
	G!(x[ 2], x[ 6], x[10], x[14]);
	G!(x[ 3], x[ 7], x[11], x[15]);
	// Diagonal step
	G!(x[ 0], x[ 5], x[10], x[15]);
	G!(x[ 1], x[ 6], x[11], x[12]);
	G!(x[ 2], x[ 7], x[ 8], x[13]);
	G!(x[ 3], x[ 4], x[ 9], x[14]);	
}


#[inline]
fn pad(output: &mut [u8], outlen: uint, input: &[u8], inlen: uint) {
	for x in output.mut_iter() { *x = 0u8; }
	copy_memory(output, input);
	output[inlen]       = 0x01;
	output[outlen - 1] |= 0x80;
}

#[inline]
fn verify(x: &[u8], y: &[u8]) -> bool {
	if x.len() != y.len() { 
		return false; 
	}
	let mut r : u8 = 0;
	for (i, j) in x.iter().zip(y.iter()) {
		r |= *i ^ *j;
	}
	return r == 0;
}

enum Tag {
	HeaderTag  = 1 << 0,
	PayloadTag = 1 << 1,
	TrailerTag = 1 << 2,
	FinalTag   = 1 << 3,
	BranchTag  = 1 << 4,
	MergeTag   = 1 << 5
}

pub enum WordSize {
	Norx32 = 32,
	Norx64 = 64
}

pub struct Config(pub WordSize, pub uint, pub uint, pub uint);

fn is_valid_config(cfg: Config) -> bool {
	let Config(w,r,d,a) = cfg;
	if r == 0 || r > 63 { return false; }
	if d != 1 { return false; } /* TODO: parallel modes */
	if a > (w as uint) * NORX_A || a % 8 != 0 { return false; }
	return true;
}

struct Sponge<T> {
	s : [T, ..NORX_B],
	r : uint,
	d : uint,
	a : uint
}

impl<T: Int> Sponge<T> {

	fn permute(&mut self) {
		for _ in range(0, self.r) {
			F(&mut self.s);
		}
	}

	fn inject_tag(&mut self, tag: Tag) {
		self.s[15] = self.s[15] ^ cast(tag as uint).expect("bad tag");
	}

	fn inject_param(&mut self) {
		let w = bits::<T>();
		let mut p : T = Zero::zero();
		p = p | cast(self.r << 26u).unwrap();
		p = p | cast(self.d << 18u).unwrap();
		p = p | cast(     w << 10u).unwrap();
		p = p | cast(self.a <<  0u).unwrap();
		self.s[14] = self.s[14] ^ p;
		self.permute();
	}

	fn init(&mut self, n: &[u8], k: &[u8]) {
		let w = bytes::<T>();
		let (u0, u1, u2, u3) = constants::<T>().expect("constant loading failure");
		self.s[ 0] = u0;
		self.s[ 1] = load_le(n.slice_from(0*w));
		self.s[ 2] = load_le(n.slice_from(1*w));
		self.s[ 3] = u1;
		self.s[ 4] = load_le(k.slice_from(0*w));
		self.s[ 5] = load_le(k.slice_from(1*w));
		self.s[ 6] = load_le(k.slice_from(2*w));
		self.s[ 7] = load_le(k.slice_from(3*w));
		self.s[ 8] = u2;
		self.s[ 9] = u3;
		let (u0, u1, u2, u3) = G(u0, u1, u2, u3);
		self.s[10] = u0;
		self.s[11] = u1;
		self.s[12] = u2;
		self.s[13] = u3;
		let (u0, u1, _, _) = G(u0, u1, u2, u3);
		self.s[14] = u0;
		self.s[15] = u1;

		self.inject_param();
	}

	#[inline]
	fn absorb_block(&mut self, input : &[u8], tag: Tag) {
		let w = bytes::<T>();
		self.inject_tag(tag);
		self.permute();
		for i in range(0, NORX_R) {
			let x : T = load_le(input.slice(i*w, (i+1)*w));
			self.s[i] = self.s[i] ^ x;
		}
	}

	#[inline]
	fn absorb(&mut self, input : &[u8], tag: Tag) {
		let block_size = rate_bytes::<T>();
		if input.len() > 0 {
			let mut lastblock = [0u8, ..MAX_RATE_BYTES];
			let mut inlen  = input.len();
			let mut offset = 0;

			while inlen >= block_size {
				self.absorb_block(input.slice_from(offset), tag);
				inlen  -= block_size;
				offset += block_size;
			}

			pad(lastblock, block_size, input.slice_from(offset), inlen);
			self.absorb_block(lastblock.slice_to(block_size), tag);
		}
	}

	pub fn absorb_header(&mut self, input : &[u8]) {
		self.absorb(input, HeaderTag);
	}

	pub fn absorb_trailer(&mut self, input : &[u8]) {
		self.absorb(input, TrailerTag);
	}

	fn encrypt_block(&mut self, output: &mut [u8], input: &[u8]) {			
		let w = bytes::<T>();
		self.inject_tag(PayloadTag);
		self.permute();
		for i in range(0, NORX_R) {
			self.s[i] = self.s[i] ^ load_le(input.slice(i*w, (i+1)*w));
			store_le(output.mut_slice(i*w, (i+1)*w), self.s[i]);
		}
	}

	pub fn encrypt_payload(&mut self, output: &mut [u8], input: &[u8]) {

		let block_size = rate_bytes::<T>();
		if input.len() > 0 {
			let mut lastblock1 = [0u8, ..MAX_RATE_BYTES];
			let mut lastblock2 = [0u8, ..MAX_RATE_BYTES];
			let mut inlen  = input.len();
			let mut offset = 0;
			while inlen >= block_size {
				self.encrypt_block(output.mut_slice_from(offset), input.slice_from(offset));
				inlen  -= block_size;
				offset += block_size;
			}
			pad(lastblock1, block_size, input.slice_from(offset), inlen);
			self.encrypt_block(lastblock2.mut_slice_to(block_size), 
				               lastblock1.slice_to(block_size));
			copy_memory(output.mut_slice_from(offset), lastblock2.slice_to(inlen));
		}
	}

	fn decrypt_block(&mut self, output: &mut [u8], input: &[u8]) {
		let w = bytes::<T>();
		self.inject_tag(PayloadTag);
		self.permute();
		for i in range(0, NORX_R) {
			let x : T = load_le(input.slice_from(i*w));
			store_le(output.mut_slice_from(i*w), self.s[i] ^ x);
			self.s[i] = x;
		}
	}

	fn decrypt_lastblock(&mut self, output: &mut [u8], input: &[u8]) {
		let w = bytes::<T>();
		let block_size = rate_bytes::<T>();
		
		self.inject_tag(PayloadTag);
		self.permute();

		let mut lastblock = [0u8,..MAX_RATE_BYTES];
		for i in range(0, NORX_R) {
			store_le(lastblock.mut_slice_from(i*w), self.s[i]);
		}

		copy_memory(lastblock, input);
		lastblock[input.len()]  ^= 0x01u8;
		lastblock[block_size-1] ^= 0x80u8;

		for i in range(0, NORX_R) {
			let x : T = load_le(lastblock.slice_from(i*w));
			store_le(lastblock.mut_slice_from(i*w), self.s[i] ^ x);
			self.s[i] = x;
		}

		copy_memory(output, lastblock.slice_to(input.len()));
	}

	pub fn decrypt_payload(&mut self, output: &mut [u8], input: &[u8]) {
		let block_size = rate_bytes::<T>();
		if input.len() > 0 {
			let mut inlen  = input.len();
			let mut offset = 0;
			while inlen >= block_size {
				self.decrypt_block(output.mut_slice_from(offset), input.slice_from(offset));
				inlen  -= block_size;
				offset += block_size;
			}
			self.decrypt_lastblock(output.mut_slice_from(offset), input.slice_from(offset));
		}
	}

	pub fn finalize(&mut self, tag: &mut [u8]) {
		let w = bytes::<T>();
		let mut lastblock = [0u8, ..MAX_RATE_BYTES];
		self.inject_tag(FinalTag);
		self.permute();
		self.permute();
		for i in range(0, NORX_R) {
			store_le(lastblock.mut_slice_from(i*w), self.s[i]);
		}
		copy_memory(tag, lastblock.slice_to(self.a / 8));
	}

	pub fn new(cfg: Config, n: &[u8], k: &[u8]) -> Option<Sponge<T>> {
		let Config(_, r, d, a) = cfg;
		if !is_valid_config(cfg) { return None; }
		if k.len() != key_bytes::<T>() { return None; }
		if n.len() != nonce_bytes::<T>() { return None; }
		let mut s : Sponge<T> = Sponge{s : [Zero::zero(), ..16], r : r, d : d, a : a};
		s.init(n, k);
		return Some(s);
	}
}

#[unsafe_destructor]
impl<T : Zero> Drop for Sponge<T> {
	fn drop(&mut self) {
		for x in self.s.mut_iter() {
			*x = Zero::zero();
		}
	}
}



fn _encrypt<T: Int>(h: &[u8], m: &[u8], t: &[u8], n: &[u8], k: &[u8], cfg: Config) -> Option<Vec<u8>> {
	let Config(_,_,_,abits) = cfg;
	let alen = abits / 8;
	let mlen = m.len();
	let clen = mlen + alen;

	let mut c = Vec::from_elem(clen, 0u8);
	let mut s : Sponge<T> = match Sponge::new(cfg, n, k) {
		Some(s) => s,
		 None   => return None
	};
	s.absorb_header(h);
	s.encrypt_payload(c.mut_slice_to(mlen), m);
	s.absorb_trailer(t);
	s.finalize(c.mut_slice_from(mlen));

	return Some(c);
}

fn _decrypt<T: Int>(h: &[u8], c: &[u8], t: &[u8], n: &[u8], k: &[u8], cfg: Config) -> Option<Vec<u8>> {
	let Config(_,_,_,abits) = cfg;
	let alen = abits / 8;
	let clen = c.len();
	let mlen = clen - alen;
	if clen < alen {
		return None;
	}
	let mut m = Vec::from_elem(mlen, 0u8);
	let mut a : [u8, ..32] = [0, ..32];
	let mut s : Sponge<T> = match Sponge::new(cfg, n, k) {
		Some(s) => s,
		None    => return None
	};

	s.absorb_header(h);
	s.decrypt_payload(m.as_mut_slice(), c.slice_to(mlen));
	s.absorb_trailer(t);
	s.finalize(a);

	if verify(c.slice_from(mlen), a.slice_to(alen)) {
		return Some(m);
	} else { 
		return None; 
	}
}

pub fn encrypt(h: &[u8], m: &[u8], t: &[u8], n: &[u8], k: &[u8], cfg: Config) -> Option<Vec<u8>> {
	let Config(w, _, _, _) = cfg;
	match w {
		Norx32 => _encrypt::<u32>(h, m, t, n, k, cfg),
		Norx64 => _encrypt::<u64>(h, m, t, n, k, cfg),
	}
}

pub fn decrypt(h: &[u8], c: &[u8], t: &[u8], n: &[u8], k: &[u8], cfg: Config) -> Option<Vec<u8>> {
	let Config(w, _, _, _) = cfg;
	match w {
		Norx32 => _decrypt::<u32>(h, c, t, n, k, cfg),
		Norx64 => _decrypt::<u64>(h, c, t, n, k, cfg),
	}
}

macro_rules! defmodule(
	($name: ident, $W: ident, $R: expr, $D: expr, $A: expr) => 
	(
		static W : WordSize = $W;
		static R : uint = $R;
		static D : uint = $D;
		static A : uint = $A;

		pub fn encrypt(h: &[u8], m: &[u8], t: &[u8], n: &[u8], k: &[u8]) -> Vec<u8> {
			base::encrypt(h, m, t, n, k, base::Config(W, R, D, A)).expect("norx: incorrect key or nonce size")
		}

		pub fn decrypt(h: &[u8], c: &[u8], t: &[u8], n: &[u8], k: &[u8]) -> Option<Vec<u8>> {
			base::decrypt(h, c, t, n, k, base::Config(W, R, D, A))
		}

		#[test]
		pub fn test() {
			static L  : uint = 256;
			static K  : uint = ($W as uint) * 4u / 8u;
			static N  : uint = ($W as uint) * 2u / 8u; 
			static T  : uint = K;
			let mut w : [u8, ..L] = [0, ..L];
			let mut h : [u8, ..L] = [0, ..L];
			let mut k : [u8, ..K] = [0, ..K];
			let mut n : [u8, ..N] = [0, ..N];

			for i in range(0, N) {
				n[i] = (i * 181 + 123) as u8;
			}

			for i in range(0, K) {
				k[i] = (i * 191 + 123) as u8;
			}

			for i in range(0, L) {
				h[i] = (i * 193 + 123) as u8;
				w[i] = (i * 197 + 123) as u8;
			}

			for i in range(0, L) {
				let j = T * i + i*(i-1)/2;
				let mut c = encrypt(h.slice_to(i), w.slice_to(i), [], n, k);
				assert!(c.as_slice() == kat.slice(j, j + i + T));
				let m = decrypt(h.slice_to(i), c.as_slice(), [], n, k).expect("bad ciphertext");
				assert!(m.as_slice() == w.slice_to(i));
				// This one is expected to fail
				*c.get_mut(i) ^= 1;
				match decrypt(h.slice_to(i), c.as_slice(), [], n, k) {
					Some(_) => assert!(false),
					None    => assert!(true)
				}
			}
		}

	)
)

