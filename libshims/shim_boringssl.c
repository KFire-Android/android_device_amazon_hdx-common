/*
 * Copyright (C) 2017 The LineageOS Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <openssl/cipher.h>
#include <openssl/ssl.h>

int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *out_len) {
	return EVP_EncryptFinal_ex(ctx, out, out_len);
}

int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *out_len) {
	return EVP_DecryptFinal_ex(ctx, out, out_len);
}

int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, uint8_t *out, int *out_len) {
	if (ctx->encrypt) {
		return EVP_EncryptFinal(ctx, out, out_len);
	} else {
		return EVP_DecryptFinal(ctx, out, out_len);
	}
}

#define OPENSSL_CTRL_SET_MSG_CALLBACK_ARG		16
#define OPENSSL_CTRL_OPTIONS				32
#define OPENSSL_CTRL_MODE				33
#define OPENSSL_CTRL_GET_READ_AHEAD			40
#define OPENSSL_CTRL_SET_READ_AHEAD			41
#define OPENSSL_CTRL_GET_MAX_CERT_LIST			50
#define OPENSSL_CTRL_SET_MAX_CERT_LIST			51
#define OPENSSL_CTRL_SET_MAX_SEND_FRAGMENT		52
#define OPENSSL_CTRL_GET_RI_SUPPORT			76
#define OPENSSL_CTRL_CLEAR_OPTIONS			77
#define OPENSSL_CTRL_CLEAR_MODE				78

long SSL_ctrl(SSL *s, int cmd, long larg, void *parg) {
	long l;

	switch (cmd) {
		case OPENSSL_CTRL_GET_READ_AHEAD:
			return SSL_get_read_ahead(s);

		case OPENSSL_CTRL_SET_READ_AHEAD:
			l = SSL_get_read_ahead(s);
			SSL_set_read_ahead(s, (int)larg);
			return l;

		case OPENSSL_CTRL_SET_MSG_CALLBACK_ARG:
			SSL_set_msg_callback(s, parg);
			return 1;

		case OPENSSL_CTRL_OPTIONS:
			return SSL_set_options(s, larg);

		case OPENSSL_CTRL_CLEAR_OPTIONS:
			return SSL_clear_options(s, larg);

		case OPENSSL_CTRL_MODE:
			return SSL_set_mode(s, larg);

		case OPENSSL_CTRL_CLEAR_MODE:
			return SSL_clear_mode(s, larg);

		case OPENSSL_CTRL_GET_MAX_CERT_LIST:
			return SSL_get_max_cert_list(s);

		case OPENSSL_CTRL_SET_MAX_CERT_LIST:
			l = SSL_get_max_cert_list(s);
			SSL_set_max_cert_list(s, larg);
			return l;

		case OPENSSL_CTRL_SET_MAX_SEND_FRAGMENT:
			if (larg < 512 || larg > SSL3_RT_MAX_PLAIN_LENGTH)
				return 0;
			SSL_set_max_send_fragment(s, larg);
			return 1;

		case OPENSSL_CTRL_GET_RI_SUPPORT:
			if (s->s3)
				return SSL_get_secure_renegotiation_support(s);
			else return 0;

		default:
			// return(s->method->ssl_ctrl(s,cmd,larg,parg));
			return 0;
	}
}

void ENGINE_cleanup(void) {
	// DO NOTHING
}

void OBJ_cleanup(void) {
	// DO NOTHING
}
