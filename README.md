# ddosmon

ddosmon is a network analysis platform which is designed to find anomalous
network patterns such as DDoS attacks and act on them automatically.  It can
do this either by directly sniffing or acting on netflow data export streams.

It is used by a few hosting providers and datacenters.

## compiling

We recommend running ddosmon as a special user with appropriate ACL to access
network devices if needed.  You should compile ddosmon as that user:

	specialuser@box:~/ddosmon-source$ ./configure --prefix=$HOME/ddosmon-home
	specialuser@box:~/ddosmon-source$ make
	specialuser@box:~/ddosmon-source$ make install

Then edit `etc/ddosmon.conf.sample` in `$HOME/ddosmon-home` as needed and save
it as `etc/ddosmon.conf`.

Run ddosmon by invoking `bin/ddosmon` in `$HOME/ddosmon-home`.

## custom modules, support contracts, etc.

You can get custom support contracts, development, and other ddosmon-related
services through my consulting business, [TortoiseLabs](http://tortois.es).

Feel free to get in touch.
