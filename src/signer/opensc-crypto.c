#include "signer.h"
#include "opensc-crypto.h"

#define DBG(x) { x; }

extern int ask_and_verify_pin_code(struct sc_pkcs15_card *p15card,
				   struct sc_pkcs15_object *pin);

void
sc_close(struct sc_priv_data *priv)
{
	if (priv->p15card) {
		sc_pkcs15_unbind(priv->p15card);
		priv->p15card = NULL;
	}
	if (priv->card) {
		sc_disconnect_card(priv->card, 0);
		priv->card = NULL;
	}
	if (priv->ctx) {
		sc_release_context(priv->ctx);
		priv->ctx = NULL;
	}
}

static int 
sc_init(struct sc_priv_data *priv)
{
	int r;

	r = sc_establish_context(&priv->ctx, "opensc-signer");
	if (r)
		goto err;
	r = sc_connect_card(priv->ctx->reader[priv->reader_id], 0, &priv->card);
	if (r)
		goto err;
	r = sc_pkcs15_bind(priv->card, &priv->p15card);
	if (r)
		goto err;
	return 0;
err:
	sc_close(priv);
	return r;
}

static int sc_private_decrypt(int flen, u_char *from, u_char *to, RSA *rsa,
			      int padding)
{
	int r;
	struct sc_priv_data *priv;
	struct sc_pkcs15_object *key, *pin;

	if (padding != RSA_PKCS1_PADDING)
		return -1;	
	priv = (struct sc_priv_data *) RSA_get_app_data(rsa);
	if (priv == NULL)
		return -1;
	if (priv->p15card == NULL) {
		sc_close(priv);
		r = sc_init(priv);
		if (r) {
#if 0
			error("SmartCard init failed: %s", sc_strerror(r));
#endif
			goto err;
		}
	}
	r = sc_pkcs15_find_prkey_by_id(priv->p15card, &priv->cert_id, &key);
	if (r) {
#if 0
		error("Unable to find private key from SmartCard: %s", sc_strerror(r));
#endif
		goto err;
	}
	r = sc_pkcs15_find_pin_by_auth_id(priv->p15card, &key->auth_id, &pin);
	if (r) {
#if 0
		error("Unable to find PIN object from SmartCard: %s", sc_strerror(r));
#endif
		goto err;
	}
	r = ask_and_verify_pin_code(priv->p15card, pin);
	if (r) {
		if (r == -2) /* User cancelled */
			goto err;
		goto err;
	}
	r = sc_pkcs15_decipher(priv->p15card, key->data, from, flen, to, flen);
	if (r < 0) {
#if 0
		error("sc_pkcs15_decipher() failed: %s", sc_strerror(r));
#endif
		goto err;
	}
	return r;
err:
	sc_close(priv);
	return -1;
}

static int
sc_private_encrypt(int flen, u_char *from, u_char *to, RSA *rsa, int padding)
{
#if 0
	error("unsupported function sc_private_encrypt() called");
#endif
	return -1;
}

static int
sc_sign(int type, u_char *m, unsigned int m_len,
	unsigned char *sigret, unsigned int *siglen, RSA *rsa)
{
	int r;
	struct sc_priv_data *priv;
	struct sc_pkcs15_object *key, *pin;
	
	priv = (struct sc_priv_data *) RSA_get_app_data(rsa);
	if (priv == NULL)
		return -1;
#if 0
	debug("sc_sign() called on cert %02X: type = %d, m_len = %d",
	      priv->cert_id.value[0], type, m_len);
#endif
	DBG(printf("sc_sign() called\n"));
	if (priv->p15card == NULL) {
		sc_close(priv);
		r = sc_init(priv);
		if (r) {
			DBG(printf("SmartCard init failed: %s", sc_strerror(r)));
			goto err;
		}
	}
	r = sc_pkcs15_find_prkey_by_id(priv->p15card, &priv->cert_id, &key);
	if (r) {
		DBG(printf("Unable to find private key from SmartCard: %s", sc_strerror(r)));
		goto err;
	}
	r = sc_pkcs15_find_pin_by_auth_id(priv->p15card, &key->auth_id, &pin);
	if (r) {
		DBG(printf("Unable to find PIN object from SmartCard: %s", sc_strerror(r)));
		goto err;
	}
	r = ask_and_verify_pin_code(priv->p15card, pin);
	if (r) {
		if (r == -2) /* User cancelled */
			goto err;
		goto err;
	}
	DBG(printf("PIN code received successfully.\n"));
	r = sc_pkcs15_compute_signature(priv->p15card, key,
					SC_ALGORITHM_RSA_HASH_SHA1 | SC_ALGORITHM_RSA_PAD_PKCS1,
					m, m_len, sigret, RSA_size(rsa));
	if (r < 0) {
		DBG(printf("sc_pkcs15_compute_signature() failed: %s", sc_strerror(r)));
		goto err;
	}
	*siglen = r;
	DBG(printf("Received signature from card (%d bytes).\n", r));
	return 1;
err:
	printf("Returning with error %s\n", sc_strerror(r));
	sc_close(priv);
	return 0;
}

static int (*orig_finish)(RSA *rsa) = NULL;

static int
sc_finish(RSA *rsa)
{
	struct sc_priv_data *priv;

	DBG(printf("sc_finish() called\n"));
	priv = RSA_get_app_data(rsa);
	if (priv != NULL) {
		priv->ref_count--;
		if (priv->ref_count == 0) {
			sc_close(priv);
			free(priv);
		}
	}
	if (orig_finish)
		orig_finish(rsa);
	return 1;
}

static RSA_METHOD libsc_rsa =
{
	"OpenSC",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	0,
	NULL,
};

RSA_METHOD * sc_get_method(void)
{
	RSA_METHOD *def;

	def = RSA_get_default_method();

        orig_finish             = def->finish;

	/* overload */
	libsc_rsa.rsa_priv_enc	= sc_private_encrypt;
	libsc_rsa.rsa_priv_dec	= sc_private_decrypt;
	libsc_rsa.rsa_sign	= sc_sign;
        libsc_rsa.finish        = sc_finish;

	/* just use the OpenSSL version */
	libsc_rsa.rsa_pub_enc   = def->rsa_pub_enc;
	libsc_rsa.rsa_pub_dec   = def->rsa_pub_dec;
	libsc_rsa.rsa_mod_exp	= def->rsa_mod_exp;
	libsc_rsa.bn_mod_exp	= def->bn_mod_exp;
	libsc_rsa.init		= def->init;
	libsc_rsa.flags		= def->flags | RSA_FLAG_SIGN_VER;
	libsc_rsa.app_data	= def->app_data;
	libsc_rsa.rsa_verify	= def->rsa_verify;

	return &libsc_rsa;
}
