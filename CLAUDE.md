We are building a KNX device stack. We can run a bunch of conformance tests by running `cargo run --bin conformance-runner`. You can pass test names or subset of names as a parameter to only run specific tests. Make sure to not truncate the output of a test run as it is possibly long.

The goal is to write a KNX device stack (and possibly more later) in Rust targeting both embedded devices in a no_std and no alloc environment and embedded Linux userspace systems.

The stack needs to be conformance compliant and generic enough so that we can replace different layers and servers in the stack for different use cases when building devices. It's best to stick to existing patterns where applicable.
