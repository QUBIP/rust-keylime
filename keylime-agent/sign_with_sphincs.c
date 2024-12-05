#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define DEBUG

typedef struct {
    uint8_t* signature;
    size_t signature_len;
} SignatureResult;

SignatureResult sign_with_sphincs(const uint8_t * quote, size_t quote_len, const uint8_t * pq_priv_key, size_t pq_priv_key_len){
    SignatureResult result = {NULL, 0};

    // Controlla se l'algoritmo SPHINCS+ è abilitato
    if (!OQS_SIG_alg_is_enabled(OQS_SIG_alg_sphincs_shake_256s_simple)) {
        fprintf(stderr, "Algoritmo SPHINCS+ non disponibile!\n");
        return result; // Torna una struttura vuota
    }

    // Inizializza la struttura per SPHINCS+
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_shake_256s_simple);
    if (sig == NULL) {
        fprintf(stderr, "Errore nella creazione della struttura di firma!\n");
        return result; // Torna una struttura vuota
    }


    // Allocazione del buffer per la firma
    result.signature = malloc(sig->length_signature);
    if (result.signature == NULL) {
        fprintf(stderr, "Errore nell'allocazione della firma!\n");
        OQS_SIG_free(sig);
        return result; // Torna una struttura vuota
    }

    result.signature_len = sig->length_signature;

    // Firma
    if (OQS_SIG_sign(sig, result.signature, &sig->length_signature, quote, quote_len, pq_priv_key) != OQS_SUCCESS) {
        fprintf(stderr, "Errore nella firma!\n");
        free(result.signature);
        OQS_SIG_free(sig);
        return result; // Torna una struttura vuota
    }

    OQS_SIG_free(sig);
    return result; // Ritorna la struttura con i risultati
}
