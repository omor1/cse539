#include <stdio.h>
#include <stdlib.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>

int main(int argx, char *argv[])
{
	// create variables
	mbedtls_x509_crt raghu_crt;
	mbedtls_pk_context raghu_pk;
	mbedtls_x509_crt trustcenter_crt;
	
	// initialize certificates and public key
	mbedtls_x509_crt_init(&raghu_crt);
	mbedtls_pk_init(&raghu_pk);
	mbedtls_x509_crt_init(&trustcenter_crt);
	
	// read from files
	mbedtls_x509_crt_parse_file(&raghu_crt, "certificate/Raghupub.cer");
	mbedtls_pk_parse_keyfile(&raghu_pk, "certificate/Raghupri.pem",
			"raghu");
	mbedtls_x509_crt_parse_file(&trustcenter_crt,
			"certificate/Trustcenter.cer");

	// verify Raghu certificate
	// This will complain about expiration, unacceptable hash, and
	// unacceptable key. The certificate is expired, so this is good. The
	// rest is because of the default security profile of mbed TLS - it
	// disallows the use of MD5 and of RSA keys less than 2048 bits in size.
	uint32_t flags;
	mbedtls_x509_crt_verify(&raghu_crt, &trustcenter_crt, NULL, NULL,
			&flags, NULL, NULL);
	char buf[1024];
	printf("Should complain about expiration, unacceptable hash, and "
			"unacceptable key. This is OK. The certificate is "
			"expired. The default security profile of mbed TLS "
			"disallows the use of MD5 and of RSA keys less than "
			"2048 bits in size, both of which the Raghu "
			"certificate uses.\n\n");
	mbedtls_x509_crt_verify_info(buf, sizeof(buf), "", flags);
	printf("%s\n", buf);
	
	// print Raghu certificate information
	mbedtls_x509_crt_info(buf, sizeof(buf), "", &raghu_crt);
	printf("%s\n", buf);
	
	// print Raghu public key
	mbedtls_rsa_context *raghu_rsa_k = mbedtls_pk_rsa(raghu_crt.pk);
	mbedtls_mpi_write_file("Raghu public key modulus: ",
			&raghu_rsa_k->N, 10, stdout);
	mbedtls_mpi_write_file("Raghu public key exponent: ",
			&raghu_rsa_k->E, 10, stdout);
	printf("\n");
	
	// print Raghu private key
	mbedtls_rsa_context *raghu_rsa_pk = mbedtls_pk_rsa(raghu_pk);
	mbedtls_mpi_write_file("Raghu private key exponent: ",
			&raghu_rsa_pk->D, 10, stdout);
	printf("\n");
	
	// print Trustcenter public key
	mbedtls_rsa_context *trust_rsa_k = mbedtls_pk_rsa(trustcenter_crt.pk);
	mbedtls_mpi_write_file("Trustcenter public key modulus: ",
			&trust_rsa_k->N, 10, stdout);
	mbedtls_mpi_write_file("Trustcenter public key exponent: ",
			&trust_rsa_k->E, 10, stdout);
	printf("\n");
	
	// print Raghu certificate signature
	printf("Raghu certificate signature: 0x");
	for(size_t i = 0; i < raghu_crt.sig.len; i++)
		printf("%02hhX", raghu_crt.sig.p[i]);
	printf("\n\n");
	
	// encrypt and decrypt string
	const unsigned char plain[] = "Our names are Omri Mor and Ravi Teja "
			"Thutari. We are enrolled in CSE 539.";
	unsigned char cipher[128];
	size_t cipher_len;
	unsigned char plain_2[128];
	size_t plain_2_len;
	printf("Plaintext: %s\n", plain);
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
			NULL, 0);
	mbedtls_pk_encrypt(&raghu_crt.pk, plain, sizeof(plain),
			cipher, &cipher_len, sizeof(cipher),
			mbedtls_ctr_drbg_random, &ctr_drbg);
	printf("Ciphertext: 0x");
	for(size_t i = 0; i < cipher_len; i++)
		printf("%02hhX", cipher[i]);
	printf("\n");
	mbedtls_pk_decrypt(&raghu_pk, cipher, cipher_len,
			plain_2, &plain_2_len, sizeof(plain_2),
			mbedtls_ctr_drbg_random, &ctr_drbg);
	printf("Decrypted ciphertext: %s\n", plain_2);
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	
	// free variable data
	mbedtls_x509_crt_free(&raghu_crt);
	mbedtls_pk_free(&raghu_pk);
	mbedtls_x509_crt_free(&trustcenter_crt);
	
	return 0;
}
