// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Isaza Arenas

//! Iraca-3 — verificación **adversarial y diferencial** de SLH-DSA-SHA2-256s
//! (FIPS 205), la firma hash-based del NIST.
//!
//! Hermana de Iraca (leanSig, XMSS) e Iraca-2 (ML-DSA, lattice). Misma tesis: el
//! ecosistema cubre la CONFORMIDAD (vectores KAT, entradas válidas); lo que nadie
//! tiene como dueño es la capa ADVERSARIAL —qué hace `verify` ante lo que NO es una
//! firma válida: firmas mutadas, longitudes mal, mensajes/claves cruzados—. Un
//! `verify` robusto las rechaza TODAS; una que acepte alguna es maleabilidad.
//!
//! **El foso, y por qué este parámetro**: nuestro stack (quipu, feature `slh`, la
//! firma triple del perito en medico) usa **SLH-DSA-SHA2-256s vía el crate
//! `fips205`**. El diferencial (fase 2) cruza `fips205` con la segunda
//! implementación Rust independiente, `slh-dsa` de RustCrypto, EN ESE MISMO
//! parámetro: un desacuerdo es un matiz de la implementación que nuestro producto
//! consume, no una curiosidad académica.
//!
//! **Nota sobre canonicidad (la «fase 3» de Iraca-2 no aplica igual)**: una firma
//! SLH-DSA es `R ‖ SIG_FORS ‖ SIG_HT`, todo concatenación de salidas hash de
//! longitud fija —sin enteros empaquetados, sin *hint* con reglas de orden, sin
//! rangos—. No hay codificación «válida-pero-no-canónica»: cada byte es un valor
//! que `verify` recomputa. Esa rigidez estructural es justamente por qué las firmas
//! hash-based son menos maleables que las lattice, y se documenta como hallazgo
//! honesto en el README, no se fuerza una fase que aquí no tiene terreno.
//!
//! Todo corre contra el `sign`/`verify` **sin modificar**, por su API pública.

use slh_dsa::signature::{Keypair, Signer, Verifier};
use slh_dsa::{Sha2_256s, Signature, SigningKey, VerifyingKey};

pub mod diferencial;

/// Longitud de la clave pública SLH-DSA-SHA2-256s (FIPS 205): 64 bytes.
pub const PK_LEN: usize = 64;
/// Longitud de la firma SLH-DSA-SHA2-256s: 29792 bytes.
pub const SIG_LEN: usize = 29792;

/// Un par de claves SLH-DSA-SHA2-256s derivado de una semilla de 32 bytes.
pub struct Par {
    pub sk: SigningKey<Sha2_256s>,
    pub vk: VerifyingKey<Sha2_256s>,
}

/// Deriva un par DETERMINISTA de una semilla de 32 bytes, para pruebas
/// reproducibles. SLH-DSA usa tres semillas internas (`sk_seed`, `sk_prf`,
/// `pk_seed`); se derivan de la de entrada con tres bytes de dominio distintos, lo
/// justo para que semillas distintas den pares distintos sin traer un KDF.
pub fn par_desde_semilla(semilla: &[u8; 32]) -> Par {
    let mut sk_seed = *semilla;
    let mut sk_prf = *semilla;
    let mut pk_seed = *semilla;
    sk_seed[0] ^= 0x01;
    sk_prf[0] ^= 0x02;
    pk_seed[0] ^= 0x03;
    let sk = SigningKey::<Sha2_256s>::slh_keygen_internal(&sk_seed, &sk_prf, &pk_seed);
    let vk = sk.verifying_key();
    Par { sk, vk }
}

/// Firma un mensaje (determinista: `try_sign` usa `opt_rand = None`) y devuelve los
/// bytes de la firma canónica.
pub fn firmar(par: &Par, mensaje: &[u8]) -> Vec<u8> {
    let sig = par.sk.try_sign(mensaje).expect("firmar SLH-DSA");
    sig.to_vec()
}

/// Los bytes canónicos de la clave pública (64 B), para el diferencial.
pub fn pk_bytes(par: &Par) -> Vec<u8> {
    par.vk.to_vec()
}

/// Verifica una firma serializada como lo hace un consumidor real: decodifica y
/// verifica. `false` si la codificación no decodifica O si la firma no valida. Es
/// exactamente la puerta que un atacante intenta cruzar.
pub fn verificar(vk: &VerifyingKey<Sha2_256s>, mensaje: &[u8], firma: &[u8]) -> bool {
    let Ok(sig) = Signature::<Sha2_256s>::try_from(firma) else {
        return false;
    };
    vk.verify(mensaje, &sig).is_ok()
}

/// El veredicto de una campaña de abuso: cuántas variantes se probaron y cuántas
/// —que NUNCA deberían— aceptó `verify`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Veredicto {
    pub probadas: usize,
    /// Variantes NO-canónicas/mutadas/ajenas que `verify` aceptó. Debe ser 0.
    pub aceptadas_indebidas: usize,
    /// Descripción de las aceptaciones indebidas (para el informe).
    pub hallazgos: Vec<String>,
}

impl Veredicto {
    fn registrar(&mut self, acepto: bool, que: impl FnOnce() -> String) {
        self.probadas += 1;
        if acepto {
            self.aceptadas_indebidas += 1;
            if self.hallazgos.len() < 32 {
                self.hallazgos.push(que());
            }
        }
    }
    pub fn limpio(&self) -> bool {
        self.aceptadas_indebidas == 0
    }
}

/// Campaña de MALLEABILITY: sobre una firma VÁLIDA, invierte bits (barrido
/// determinista, uno de cada `salto`) y comprueba que `verify` rechaza cada
/// variante mutada. Una firma mutada que verifique es maleabilidad.
pub fn campana_malleability(par: &Par, mensaje: &[u8], salto: usize) -> Veredicto {
    let firma = firmar(par, mensaje);
    let mut v = Veredicto::default();
    let total_bits = firma.len() * 8;
    let mut i = 0;
    while i < total_bits {
        let mut mutada = firma.clone();
        mutada[i / 8] ^= 1 << (i % 8);
        let acepto = verificar(&par.vk, mensaje, &mutada);
        v.registrar(acepto, || format!("bit {i} invertido → aceptada"));
        i += salto.max(1);
    }
    v
}

/// Casos ESTRUCTURALES de abuso que un `verify` robusto debe rechazar:
/// codificaciones degeneradas, longitudes mal, y mensaje/clave cruzados.
pub fn campana_estructural(par: &Par, mensaje: &[u8], otro_mensaje: &[u8]) -> Veredicto {
    let firma = firmar(par, mensaje);
    let mut v = Veredicto::default();

    v.registrar(verificar(&par.vk, mensaje, &vec![0u8; firma.len()]), || "todo ceros".into());
    v.registrar(verificar(&par.vk, mensaje, &vec![0xFFu8; firma.len()]), || "todo 0xFF".into());
    v.registrar(verificar(&par.vk, mensaje, &firma[..firma.len() - 1]), || "truncada 1 byte".into());
    let mut mas = firma.clone();
    mas.push(0);
    v.registrar(verificar(&par.vk, mensaje, &mas), || "un byte extra".into());
    v.registrar(verificar(&par.vk, mensaje, &[]), || "vacía".into());
    v.registrar(verificar(&par.vk, otro_mensaje, &firma), || "mensaje cruzado".into());
    let otra = par_desde_semilla(&[0x5A; 32]);
    v.registrar(verificar(&otra.vk, mensaje, &firma), || "clave cruzada".into());

    v
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// CONTROL POSITIVO (D33): una firma válida DEBE verificar. Sin esto, un arnés
    /// que diga «0 aceptadas» podría ser uno que rechaza todo.
    #[test]
    fn la_firma_valida_verifica() {
        let par = par_desde_semilla(&[7u8; 32]);
        let msg = b"expediente clinico numero 42";
        let firma = firmar(&par, msg);
        assert_eq!(firma.len(), SIG_LEN, "la firma debe medir {SIG_LEN}");
        assert!(verificar(&par.vk, msg, &firma), "una firma legítima debe verificar");
    }

    /// La pareja del control (D33): una firma con UN bit cambiado NO verifica.
    #[test]
    fn un_bit_cambiado_no_verifica() {
        let par = par_desde_semilla(&[7u8; 32]);
        let msg = b"expediente clinico numero 42";
        let mut firma = firmar(&par, msg);
        firma[0] ^= 1;
        assert!(!verificar(&par.vk, msg, &firma), "un bit cambiado no debe verificar");
    }

    /// Campaña de malleability (D8: >100 operaciones): NINGUNA mutación de una firma
    /// válida verifica. Recorre ~1 de cada 1500 bits (>150 variantes) para acotar el
    /// coste sobre los ~29792 bytes de la firma.
    #[test]
    fn ninguna_mutacion_verifica() {
        let par = par_desde_semilla(&[9u8; 32]);
        let msg = b"otro mensaje distinto";
        let v = campana_malleability(&par, msg, 1500);
        assert!(v.probadas > 100, "debe probar >100 variantes, probó {}", v.probadas);
        assert!(v.limpio(), "maleabilidad: {} aceptadas: {:?}", v.aceptadas_indebidas, v.hallazgos);
    }

    /// Los casos estructurales de abuso se rechazan todos.
    #[test]
    fn los_casos_estructurales_se_rechazan() {
        let par = par_desde_semilla(&[11u8; 32]);
        let v = campana_estructural(&par, b"mensaje A", b"mensaje B");
        assert!(v.limpio(), "abuso estructural aceptado: {:?}", v.hallazgos);
    }
}
