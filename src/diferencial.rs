// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Isaza Arenas

//! Fase 2 — verificación **diferencial** de SLH-DSA-SHA2-256s (FIPS 205) entre dos
//! implementaciones Rust independientes y conformes:
//!
//! - `fips205` de integritychain — **la que consume quipu** (feature `slh`, la firma
//!   triple del perito en medico).
//! - `slh-dsa` de RustCrypto — segunda implementación, código totalmente distinto,
//!   ya atacada en la fase 1.
//!
//! La tesis: la conformidad (KAT) prueba que ambas ACEPTAN lo válido; el hueco es el
//! **desacuerdo ante lo inválido**. Si a las dos se les dan EXACTAMENTE los mismos
//! bytes (misma clave pública, mismo mensaje, misma candidata a firma) y una ACEPTA
//! mientras la otra RECHAZA, esa candidata cruza una puerta y no la otra:
//! maleabilidad en la permisiva, o interpretación divergente del estándar. Como
//! `fips205` es la que nuestro producto usa, un desacuerdo es un matiz NUESTRO.
//!
//! Las dos codificaciones son byte-compatibles por FIPS 205: clave pública 64 B
//! (pk_seed ‖ pk_root), firma 29792 B (R ‖ SIG_FORS ‖ SIG_HT). El contexto es el
//! vacío (`b""`) en las dos; y las dos usan el mismo framing FIPS 205 del mensaje
//! (`0x00 ‖ len(ctx)=0 ‖ msg`) —verificado en la fuente de `slh-dsa`—, así que los
//! cruces de control deben cerrar. Si NO cerraran, no serían intercambiables y eso
//! mismo es el hallazgo.

use crate::{firmar, pk_bytes, verificar, Par, PK_LEN, SIG_LEN};
use fips205::slh_dsa_sha2_256s as fips;
use fips205::traits::{SerDes as _, Signer as _, Verifier as _};
use slh_dsa::{Sha2_256s, VerifyingKey};

/// Verificador de la implementación que USA nuestro stack (`fips205`), con la misma
/// semántica que `crate::verificar`: recibe clave pública y candidata a firma tal
/// cual las manda el mundo, y devuelve `false` ante CUALQUIER no-conformidad —clave
/// de longitud mal, firma de longitud mal, o firma que no valida—.
pub fn verificar_fips(pk_bytes: &[u8], mensaje: &[u8], firma: &[u8]) -> bool {
    let Ok(pk_arr): Result<[u8; fips::PK_LEN], _> = pk_bytes.try_into() else {
        return false;
    };
    let Ok(pk) = fips::PublicKey::try_from_bytes(&pk_arr) else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; fips::SIG_LEN], _> = firma.try_into() else {
        return false;
    };
    pk.verify(mensaje, &sig_arr, b"")
}

/// Verificador de `slh-dsa` (RustCrypto) partiendo de bytes de clave pública crudos
/// (para la dirección inversa: `fips205` firma → `slh-dsa` verifica). `false` si la
/// clave no decodifica.
pub fn verificar_slh_desde_pk(pk_bytes: &[u8], mensaje: &[u8], firma: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::<Sha2_256s>::try_from(pk_bytes) else {
        return false;
    };
    verificar(&vk, mensaje, firma)
}

/// Un desacuerdo entre las dos implementaciones sobre la MISMA entrada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Desacuerdo {
    pub descripcion: String,
    /// ¿aceptó `slh-dsa` (RustCrypto)?
    pub slh_dsa: bool,
    /// ¿aceptó `fips205` (integritychain, la de quipu)?
    pub fips205: bool,
}

/// El veredicto de la campaña diferencial.
#[derive(Debug, Default)]
pub struct VeredictoDiferencial {
    pub probadas: usize,
    /// Entradas donde una implementación aceptó y la otra no. Debe ser 0.
    pub desacuerdos: Vec<Desacuerdo>,
    /// CONTROL POSITIVO (D30/D33): una firma `slh-dsa` válida verificada por
    /// `fips205` (cruce A→B). Debe ser `true`, o las dos no se entienden en lo
    /// válido y todo «desacuerdo» sería ruido de interop (o incompatibilidad de
    /// bytes, que sería su propio hallazgo).
    pub cruce_a_b: bool,
    /// CONTROL POSITIVO inverso: firma `fips205` válida verificada por `slh-dsa`
    /// (cruce B→A).
    pub cruce_b_a: bool,
}

impl VeredictoDiferencial {
    fn comparar(&mut self, pk: &[u8], mensaje: &[u8], candidata: &[u8], que: impl FnOnce() -> String) {
        self.probadas += 1;
        let a = verificar_slh_desde_pk(pk, mensaje, candidata);
        let b = verificar_fips(pk, mensaje, candidata);
        if a != b && self.desacuerdos.len() < 64 {
            self.desacuerdos.push(Desacuerdo { descripcion: que(), slh_dsa: a, fips205: b });
        }
    }
    /// Limpio = ningún desacuerdo Y los dos cruces de control en verde (D30).
    pub fn limpio(&self) -> bool {
        self.desacuerdos.is_empty() && self.cruce_a_b && self.cruce_b_a
    }
}

/// Campaña diferencial: sobre una clave pública compartida y un mensaje, alimenta a
/// las DOS implementaciones con el mismo corpus de candidatas —la firma válida, un
/// barrido de bit-flips, y casos estructurales— y registra toda entrada donde
/// discrepen. Antes mide los dos cruces de control (A→B y B→A) para que el «0
/// desacuerdos» sea creíble (D30).
///
/// `salto` acota el barrido de bit-flips sobre los ~29792 bytes de la firma.
pub fn campana_diferencial(par: &Par, mensaje: &[u8], salto: usize) -> VeredictoDiferencial {
    let mut v = VeredictoDiferencial::default();
    let pk = pk_bytes(par);
    let firma = firmar(par, mensaje);

    // --- Controles positivos: las dos implementaciones se entienden en lo VÁLIDO.
    // A→B: firma de slh-dsa verificada por fips205 (clave y mensaje compartidos).
    v.cruce_a_b = verificar_fips(&pk, mensaje, &firma);
    // B→A: par y firma nativos de fips205, verificados por slh-dsa.
    let (pk_f, sk_f) = fips::try_keygen().expect("keygen fips205");
    let firma_f = sk_f.try_sign(mensaje, b"", false).expect("sign fips205");
    v.cruce_b_a = verificar_slh_desde_pk(&pk_f.into_bytes(), mensaje, &firma_f);

    // --- Corpus compartido, comparado entre las dos puertas.
    // 1) La firma válida: las dos DEBEN aceptar.
    v.comparar(&pk, mensaje, &firma, || "firma válida".into());

    // 2) Barrido de bit-flips: cada mutación (uno de cada `salto`). Las dos DEBEN
    //    rechazar; si una acepta una que la otra rechaza, es maleabilidad diferencial.
    let total_bits = firma.len() * 8;
    let mut i = 0;
    while i < total_bits {
        let mut mutada = firma.clone();
        mutada[i / 8] ^= 1 << (i % 8);
        v.comparar(&pk, mensaje, &mutada, || format!("bit {i} invertido"));
        i += salto.max(1);
    }

    // 3) Estructurales: degeneradas, longitudes al límite, mensaje y clave cruzados.
    v.comparar(&pk, mensaje, &vec![0u8; SIG_LEN], || "todo ceros".into());
    v.comparar(&pk, mensaje, &vec![0xFFu8; SIG_LEN], || "todo 0xFF".into());
    v.comparar(&pk, mensaje, &firma[..firma.len() - 1], || "truncada 1 byte".into());
    let mut mas = firma.clone();
    mas.push(0);
    v.comparar(&pk, mensaje, &mas, || "un byte extra".into());
    v.comparar(&pk, mensaje, &[], || "vacía".into());
    v.comparar(&pk, b"otro mensaje", &firma, || "mensaje cruzado".into());

    // 4) Clave cruzada: la firma de `par` con la clave pública de OTRO par.
    let otro = crate::par_desde_semilla(&[0x5A; 32]);
    let pk_otro = pk_bytes(&otro);
    v.comparar(&pk_otro, mensaje, &firma, || "clave cruzada".into());

    let _ = PK_LEN;
    v
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::par_desde_semilla;

    /// CONTROL POSITIVO (D30/D33): las dos implementaciones se entienden en lo
    /// válido, en los DOS sentidos. Sin esto, el «0 desacuerdos» sería
    /// indistinguible de dos implementaciones que ni hablan el mismo formato.
    #[test]
    fn las_dos_implementaciones_se_cruzan() {
        let par = par_desde_semilla(&[3u8; 32]);
        let msg = b"cruce de conformidad";
        let pk = pk_bytes(&par);
        let firma = firmar(&par, msg);
        assert!(verificar_fips(&pk, msg, &firma), "A→B: fips205 debe aceptar la firma de slh-dsa");

        let (pk_f, sk_f) = fips::try_keygen().unwrap();
        let firma_f = sk_f.try_sign(msg, b"", false).unwrap();
        assert!(
            verificar_slh_desde_pk(&pk_f.into_bytes(), msg, &firma_f),
            "B→A: slh-dsa debe aceptar la firma de fips205"
        );
    }

    /// La pareja del control (D33): `verificar_fips` RECHAZA lo que debe. Sin esto,
    /// un `verificar_fips` que dijera `true` a todo haría la campaña ciega.
    #[test]
    fn verificar_fips_discrimina() {
        let par = par_desde_semilla(&[4u8; 32]);
        let msg = b"discriminacion fips";
        let pk = pk_bytes(&par);
        let mut firma = firmar(&par, msg);
        assert!(verificar_fips(&pk, msg, &firma), "válida acepta");
        firma[0] ^= 1;
        assert!(!verificar_fips(&pk, msg, &firma), "mutada rechaza");
        assert!(!verificar_fips(&pk, b"otro", &firmar(&par, msg)), "mensaje cruzado rechaza");
        assert!(!verificar_fips(&pk[..pk.len() - 1], msg, &firmar(&par, msg)), "clave corta rechaza");
    }

    /// El corazón de la fase 2 (D8: >100 operaciones): NINGUNA entrada del corpus
    /// compartido produce desacuerdo entre las dos implementaciones, y los dos
    /// cruces de control están en verde.
    #[test]
    fn las_dos_implementaciones_no_discrepan() {
        let par = par_desde_semilla(&[13u8; 32]);
        let v = campana_diferencial(&par, b"expediente clinico numero 42", 1500);
        assert!(v.probadas > 100, "debe comparar >100 entradas, comparó {}", v.probadas);
        assert!(v.cruce_a_b, "control A→B roto: las implementaciones no se entienden");
        assert!(v.cruce_b_a, "control B→A roto");
        assert!(v.desacuerdos.is_empty(), "{} desacuerdos: {:?}", v.desacuerdos.len(), v.desacuerdos);
    }

    /// Un mutante que fuerza un desacuerdo DEBE ser detectado (D33): si a `fips205`
    /// se le da una firma válida y a `slh-dsa` una mutada, las dos puertas devuelven
    /// valores distintos —el mecanismo que `comparar` usa para detectar—.
    #[test]
    fn un_desacuerdo_fabricado_se_detecta() {
        let par = par_desde_semilla(&[21u8; 32]);
        let msg = b"desacuerdo fabricado";
        let pk = pk_bytes(&par);
        let firma = firmar(&par, msg);
        let a = verificar_slh_desde_pk(&pk, msg, &firma);
        let mut mutada = firma.clone();
        mutada[10] ^= 0x80;
        let b = verificar_fips(&pk, msg, &mutada);
        assert!(a && !b, "el arnés debe poder ver aceptación de una puerta y rechazo de la otra");
    }
}
