ssh-otp: ssh-otp.c
	$(CC) -o $@ $< -lcrypto
