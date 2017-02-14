#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <openssl/hmac.h>

#define MAX_SKEW 1

int b32decode(const char *s, unsigned char *b)
{
    int i;

    memset(b, 0, 10);
    for (i = 0; i < 16; i++) {
        unsigned char x;
        if (isalpha(s[i])) {
            x = toupper(s[i]) - 'A';
        } else if (s[i] >= '2' && s[i] <= '7') {
            x = s[i] - '2' + 26;
        } else {
            return 0;
        }
        b[5*i / 8] |= (x << 3) >> (5*i % 8);
        if (5*i % 8 >= 4) {
            b[5*i / 8 + 1] |= x << (3 + 8 - (5*i % 8));
        }
    }
    return 1;
}

void hotp(const unsigned char *sbytes, time_t movingFactor, char *code)
{
    unsigned char data[8];
    int i, offset, bin_code, otp;

    for (i = 0; i < 8; i++) {
        data[i] = i < 4 ? 0 : movingFactor >> (56 - 8*i);
    }
    unsigned char *r = HMAC(EVP_sha1(), sbytes, 10, data, sizeof(data), NULL, NULL);
    offset = r[19] & 0xf;
    bin_code = ((r[offset] << 24) | (r[offset+1] << 16) | (r[offset+2] << 8) | r[offset+3]) & 0x7fffffff;
    otp = bin_code % 1000000;
    sprintf(code, "%06d", otp);
}

void proceed()
{
    if (getenv("SSH_ORIGINAL_COMMAND") != NULL) {
        execl("/bin/sh", "/bin/sh", "-c", getenv("SSH_ORIGINAL_COMMAND"), NULL);
    } else {
        execl(getenv("SHELL"), "-", NULL);
    }
}

int main(int argc, char *argv[])
{
    int i;
    unsigned char sbytes[10];
    char code[7], input_a[10];
    char *input;
    time_t now;

    if (argc < 2) {
        exit(1);
    }

    input = getenv("OTP_TOKEN");
    if (!input || strcmp(input, "") == 0) {
        fprintf(stderr, "Enter the validation code: ");
        if (fgets(input_a, sizeof(input_a), stdin) == NULL) {
            exit(1);
        }
        input = input_a;
    }

    if (!b32decode(argv[1], sbytes)) {
        exit(1);
    }

    now = time(NULL);
    for (i = 0; i <= MAX_SKEW; i++) {
        hotp(sbytes, now / 30 + i, code);
        if (strncmp(input, code, 6) == 0) {
            proceed();
        }
        hotp(sbytes, now / 30 - i, code);
        if (strncmp(input, code, 6) == 0) {
            proceed();
        }
    }

    fprintf(stderr, "Invalid");

    return 1;
}
