epm
===

Erlang package maker is a simple tool like https://github.com/jordansissel/fpm  that will build a deb or rpm package from your directory.

You may use it to build packages for Ubuntu, Debian or Centos from your Mac without installing any specific software
like apt or librpm.

It claims to be a drop-in replacement for fpm, but without ruby runtime requirement.

Usage
=====

I use it in the following way:

1. create tmproot
2. copy all required and compiled erlang files there
3. unpack there archive with precompiled linux binaries
4. cd tmproot and run following commands:


```bash
EPM="-s dir --url http://flussonic.com/ --description 'Videostreaming server' \
    -m 'Max Lapshin <max@flussonic.com>' \
    --vendor 'Flussonic, LLC' --license EULA --post-install ../deploy/debian/postinst \
    --pre-uninstall ../deploy/debian/prerm --post-uninstall ../deploy/debian/postrm \
    --config-files /etc/flussonic/flussonic.conf"
../epm.erl -f -t deb -n flussonic -v 4.1.14 $DEBIAN -a amd64 \
           --category net etc/init.d etc/flussonic opt
../epm.erl -f -t rpm -n flussonic -v 4.1.14 $DEBIAN -a amd64 \
           --gpg max@flussonic.com --category Server/Video etc/init.d etc/flussonic opt
```


License
=======

Do-whatever-you-want-to-MIT, but please, make a pull request if you fix any bug in it.
