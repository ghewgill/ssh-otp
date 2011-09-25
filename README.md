ssh-otp
=======

This script offers ssh logins an optional authentication code (TOTP, compatible with Google Authenticator mobile apps). It is based on a [ruby implementation by Richard Taylor][1].

Using this authentication code requires using SSH keys. Change your `authorized_keys` file to add a `command=` argument:

    command="/usr/local/bin/python /usr/bin/ssh-otp.py 4rr7kc47sc5a2fgt" ssh-dsa AAA...

Modify the paths for `python` and `ssh-otp.py` as appropriate.

The `4rr7kc47sc5a2fgt` is a secret key that you should generate yourself (obviously, don't use this one). If you like, you can [generate a new secret key at random.org][2], or use any other method you trust. They key is a 16-character base32 (a-z2-7) string, so if you're using random.org, substitute any other letters or numbers for 0, 1, 8, and 9.

Configure your Google Authenticator mobile app by adding a new entry with the same secret key. Be sure the clock on your mobile device is reasonably synchronised with your ssh server.

  [1]: https://moocode.com/posts/5-simple-two-factor-ssh-authentication
  [2]: https://www.random.org/strings/?num=10&len=16&digits=on&loweralpha=on&unique=on&format=html&rnd=new
