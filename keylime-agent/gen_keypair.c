#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define DEBUG 0
typedef struct {
    uint8_t* public_key;
    size_t public_key_len;
    uint8_t* private_key;
    size_t private_key_len;
} KeypairResult;

KeypairResult generate_sphincs_keypair() {
    KeypairResult result = {NULL, 0,NULL,0};

    // Controlla se l'algoritmo SPHINCS+ è abilitato
    if (!OQS_SIG_alg_is_enabled(OQS_SIG_alg_sphincs_shake_256s_simple)) {
        fprintf(stderr, "Algoritmo SPHINCS+ non disponibile!\n");
        return result; // Torna una struttura vuota in caso di errore
    }

    // Inizializza la struttura per SPHINCS+
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_sphincs_shake_256s_simple);
    if (sig == NULL) {
        fprintf(stderr, "Errore nella creazione della struttura di firma!\n");
        return result; // Torna una struttura vuota in caso di errore
    }

    // Imposta la lunghezza della chiave pubblica e privata
    result.public_key_len = sig->length_public_key;
    result.private_key_len = sig->length_secret_key;


    // Allocazione della chiave pubblica e della chiave segreta
    result.public_key = malloc(result.public_key_len);
    result.private_key = malloc(result.private_key_len);
    if (result.public_key == NULL || result.private_key == NULL) {
        fprintf(stderr, "Errore nell'allocazione delle chiavi!\n");
        OQS_SIG_free(sig);
        free(result.public_key);
        free(result.private_key);
        return result; // Torna una struttura vuota in caso di errore
    }

    // Generazione delle chiavi
    if (OQS_SIG_keypair(sig, result.public_key, result.private_key) != OQS_SUCCESS) {
        fprintf(stderr, "Errore nella generazione delle chiavi!\n");
        OQS_SIG_free(sig);
        free(result.public_key);
        free(result.private_key);
        return result; // Torna una struttura vuota in caso di errore
    }


#if DEBUG
    // Stampa della chiave pubblica
    fprintf(stdout, "Chiave pubblica: ");
    for (size_t i = 0; i < result.public_key_len; i++) {
        fprintf(stdout, "%02X", result.public_key[i]);
    }
    fprintf(stdout, "\n");

    // Stampa della chiave privata
    fprintf(stdout, "Chiave privata: ");
    for (size_t i = 0; i < result.private_key_len; i++) {
        fprintf(stdout, "%02X", result.private_key[i]);
    }
    fprintf(stdout, "\n");
    
#endif

    // Liberazione della memoria non più necessaria
    OQS_SIG_free(sig);

    return result; // Ritorna la struttura con la chiave pubblica
}
