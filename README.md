packetdump - a high-speed compressing packet-sniffer
=============================================

This is a high-speed (10gig) packet-sniffer that compresses packets as it
writes to disk. I wrote it because the packet logging features of `tcpdump`
are slow, but extra special slow when attempting to compress files after
they've been written uncompressed to the disk when rotating files.

Typical usage is simply something like this:

  packetdump -i eth0 -G 3600 -w foo-%y%m%d-%H%M%S.pcap.lz4

This will recognize the `.lz4` extension, and automatically use the LZ4
compression method. The files can then be expanded using the default `lz4`
tool from the command-line.

The LZ4 algorithm isn't as good at compression as alternatives, but is a lot
faster.

Because of the `-G 3600` option, it will rotate files on an hourly basis.
When it creates a new file, it'll use the timestamp specifiers to (the
options with %) to use the current timestamp as the filename.

Unlike `tcdump`, this program aligns its rotations. In other words, it rotates
on the hour (when 3600 seconds is specified), such as 1:00pm, 2:00pm, 3:00pm,
etc. In contrast, `tcpdump` would rotate exaclty one hour from program
startup, and every hour after. So if the program started at 1:47pm, then
`tcpdump` would rotate at 2:47pm, 3:47pm, and so forth. This means that the
first file will be (likley) shorter than the others, since it will have less
than an hour's data.

For higher speed sniffing, the PF_RING/ZC drivers can be used for Intel 10gig
cards. Simply put the letters `zc:` in front of the interface name, and it
should be automatically selected, as long as PF_RING is installed.


