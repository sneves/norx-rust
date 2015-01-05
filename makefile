all: libnorx

libnorx: norx.rs base.rs norx6441.rs norx6461.rs norx3241.rs norx3261.rs
	rustc -C opt-level=3 norx.rs --crate-type lib

example: libnorx example.rs
	rustc -C opt-level=3 example.rs -L .

test: 
	rustc -C opt-level=3 norx.rs --crate-type lib --test
	./norx

clean:
	rm -f norx example *.rlib
