import base64
import hotp
import os
import sys
import time

if len(sys.argv) < 2:
    sys.exit(1)

secret = sys.argv[1]

sys.stderr.write("Enter the validation code: ")
code = raw_input()

if code != hotp.hotp(base64.b32decode(secret, True), int(time.time() / 30)):
    print >>sys.stderr, "Invalid"
    sys.exit(1)

orig = os.getenv("SSH_ORIGINAL_COMMAND")
if orig:
    os.execl("/bin/sh", "/bin/sh", "-c", os.getenv("SSH_ORIGINAL_COMMAND"))
else:
    os.execl(os.getenv("SHELL"), "-" + os.path.basename(os.getenv("SHELL")))
