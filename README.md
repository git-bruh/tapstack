# tunstack

Small userspace TCP/IP stack based on TUN devices, implements:

- [x] Handshake
- [x] Sliding window
- [x] Out-of-order packet reassembly
- [x] Retransmissions (including RTO calculation)
- [x] Socket close & reset
- [ ] Respect MSS
- [ ] Nagle's algorithm
- [ ] SWS avoidance
- [ ] Zero-Window probes
- [ ] Congestion control
- [ ] SACK
- [ ] Timestamps

# Usage

Build the project using `cargo`, setup `iptables` rules to allow the `TUN` interface to handle traffic, and run it!

```sh
$ cargo build
# ./scripts/iptables_rules.sh
# ./target/debug/tunstack
```

# Similar Projects

- [Level-IP](https://github.com/saminiir/level-ip)

- [tapip](https://github.com/chobits/tapip)

- [rust-tcp](https://github.com/jonhoo/rust-tcp)

- [smoltcp](https://github.com/smoltcp-rs/smoltcp)

- [tcp_ip](https://github.com/rustp2p/tcp_ip)

- [PicoTCP](https://github.com/virtualsquare/picotcp)

- [MicroTCP](https://github.com/cozis/microtcp)

# References

- [Let's code a TCP/IP stack](https://www.saminiir.com/lets-code-tcp-ip-stack-1-ethernet-arp)

- [Write TCP/IP Stack by Yourself](https://beardnick.github.io/qianz.github.io/posts/write_tcp_ip_stack_by_yourself_1)

- [RFC - Transmission Control Protocol (TCP)](https://www.ietf.org/rfc/rfc9293.html)

- [RFC - Computing TCP's Retransmission Timer](https://www.rfc-editor.org/rfc/rfc6298)

- [RFC - TCP Congestion Control](https://www.rfc-editor.org/rfc/rfc5681)

- [RFC - TCP Extensions for High Performance](https://www.rfc-editor.org/rfc/rfc7323)
