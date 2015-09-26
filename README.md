No Nonsense FTP/TFTP Server
===========================
[![Travis Status][]][Travis] [![Coverity Status][]][Coverity Scan]

uftpd is a UNIX daemon with sane built-in defaults.  It just works.


Features
--------

* FTP and/or TFTP
* No configuration file
* Runs from standard UNIX inetd, or standalone
* Listens to `ftp/tcp` and `tftp/udp` found in `/etc/services`
* Serves files from the ftp user's `$HOME`, found in `/etc/passwd`
* Privilege separation, drops root privileges before serving files
* Possible to use symlinks outside of the home directory (INSECURE,
  but user friendly)
* Possible to use group writable home directory (INSECURE, but again
  user friendly)


Caveat
------

uftpd is not made for secure installations, it is primarily targeted at
home users and developers in need of a simple TFTP/FTP server.  As such
it allows symlinks outside the FTP home, as well as a group writable FTP
home directory &mdash; i.e, user-friendly features that can easily cause
security breaches, but also very useful for people who do not care and
just want their FTP server to work.

*Seriously*, we do not advise you to ignore any security aspect of your
installation.  If security is a concern for you, consider using another
TFTP/FTP server!

That being said, a lot of care has been taken to lock down and secure
uftpd by default.  So, if you refrain from symlinking stuff from your
home directory and carefully set up strict permissions on that
directory, then uftpd is likely as secrure as any other TFTP/FTP server.


Download
--------

Although the project makes heavy use of GitHub, it is *not* recommended
to use the ZIP file links GitHub provides.  Instead, we recommend using
proper tarball releases from [the FTP][], or the [releases page][].

The GitHub *Download ZIP* links, and ZIP files on the [releases page][],
do not include files from the GIT submodules.  The Makefile makes up for
this, but is not 100% foolproof.

Alternatively, instead of building the sources, you can install the
latest [pre-built package][.deb] &mdash; or build and install your own
package.  Installing the package takes care of setting up inetd for you.
Use `make package` to build the `.deb` package file.

See below if you want to contribute.


Running
-------

To start uftpd in the background as an FTP-only server, simply call

    sudo ./uftpd

To enable both FTP and TFTP, call

    sudo ./uftpd -f -t

The `-f` and `-t` can be given alternative Internet port arguments, e.g.
`-f2121` to start FTP on port 2121.  For other command line options and
more details, see the man page or the output from the command:
<kdb>`uftpd --help`</kdb>

To run uftpd from the Internet super server, inetd, use the following
two lines in `/etc/inetd.conf`:

    ftp		stream	tcp	nowait	root	/usr/sbin/uftpd -i -f
    tftp	dgram	udp	wait	root	/usr/sbin/uftpd -i -t

Remember to activate your changes to inetd by reloading the service or
sending `SIGHUP` to it.  Another inetd server may use different syntax.
Like the inetd that comes built-in to [Finit][], in `/etc/finit.conf`:

    inetd ftp/tcp   nowait /usr/sbin/uftpd -i -f -- The uftpd FTP server
    inetd tftp/udp    wait /usr/sbin/uftpd -i -t -- The uftpd TFTP server


Origin & References
-------------------

Originally based on [FtpServer][] by [Xu Wang][], uftpd is a complete
rewrite with TFTP support by [Joachim Nilsson][], maintained at
[GitHub][].  If you want to contribute, check out the code, including
the submodules:

	git clone https://github.com/troglobit/uftpd
	cd uftpd
	make submodules

When you pull from upstream, remember to also update the submodules
using `git submodule update`.


[.deb]:            http://ftp.troglobit.com/uftpd/uftpd_1.9-1_amd64.deb
[Joachim Nilsson]: http://troglobit.com
[the FTP]:         http://ftp.troglobit.com/uftpd/
[releases page]:   https://github.com/troglobit/uftpd/releases
[Xu Wang]:         https://github.com/xu-wang11/
[FtpServer]:       https://github.com/xu-wang11/FtpServer
[GitHub]:          https://github.com/troglobit/uftpd
[Finit]:           https://github.com/troglobit/finit
[Travis]:          https://travis-ci.org/troglobit/uftpd
[Travis Status]:   https://travis-ci.org/troglobit/uftpd.png?branch=master
[Coverity Scan]:   https://scan.coverity.com/projects/2947
[Coverity Status]: https://scan.coverity.com/projects/2947/badge.svg

<!--
  -- Local Variables:
  -- mode: markdown
  -- End:
  -->
