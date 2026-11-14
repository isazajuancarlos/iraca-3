// SPDX-License-Identifier: MIT OR Apache-2.0
//! Medición reproducible del arnés de Iraca-3 sobre SLH-DSA-SHA2-256s (FIPS 205).
//! `cargo run --release --example medir`

use iraca3::diferencial;

fn main() {
    let par = iraca3::par_desde_semilla(&[3u8; 32]);
    let msg = b"radiografia de torax, paciente 1024, 2005-03-11";

    // Barrido: SLH-DSA-256s tiene firma de 29792 B (238336 bits). La verificación es
    // barata; el barrido con salto=13 prueba >18000 variantes en minutos, muestreo
    // denso y uniforme sin el coste de recorrer todos los bits.
    let salto = 13;

    // ===== FASE 1: abuso de UNA implementación (slh-dsa RustCrypto) =====
    let mal = iraca3::campana_malleability(&par, msg, salto);
    let est = iraca3::campana_estructural(&par, msg, b"otro mensaje");

    println!("== Iraca-3 · SLH-DSA-SHA2-256s (FIPS 205) ==");
    println!("-- FASE 1: abuso de slh-dsa 0.1.0 (RustCrypto) --");
    println!(
        "malleability (barrido 1 de cada {salto} bits): {} variantes probadas, {} aceptadas indebidamente",
        mal.probadas, mal.aceptadas_indebidas
    );
    println!(
        "abuso estructural (ceros/unos/longitud/mensaje-cruzado/clave-cruzada): {} probadas, {} aceptadas",
        est.probadas, est.aceptadas_indebidas
    );
    if mal.limpio() && est.limpio() {
        println!("  VEREDICTO FASE 1: SECO — verify rechaza toda variante no canónica/mutada/ajena.");
    } else {
        println!("  VEREDICTO FASE 1: HALLAZGO");
        for h in mal.hallazgos.iter().chain(est.hallazgos.iter()) {
            println!("    - {h}");
        }
    }

    // ===== FASE 2: DIFERENCIAL slh-dsa ↔ fips205 (la de quipu) =====
    let dif = diferencial::campana_diferencial(&par, msg, salto);

    println!("-- FASE 2: diferencial slh-dsa 0.1.0 ↔ fips205 0.4.1 (la que usa quipu) --");
    println!(
        "cruces de control (ambos VERDE, D30): A→B (slh-dsa firma, fips205 verifica) = {}, B→A = {}",
        dif.cruce_a_b, dif.cruce_b_a
    );
    println!(
        "corpus compartido (firma válida + barrido + estructurales + cruzados): {} entradas comparadas, {} desacuerdos accept/reject",
        dif.probadas,
        dif.desacuerdos.len()
    );
    if dif.limpio() {
        println!(
            "  VEREDICTO FASE 2: SECO — las dos implementaciones conformes ACUERDAN en cada entrada; ningún desacuerdo explotable."
        );
    } else if !dif.cruce_a_b || !dif.cruce_b_a {
        println!(
            "  VEREDICTO FASE 2: NO CONCLUYENTE — un cruce de control falló; el «0 desacuerdos» no es creíble (D30)."
        );
    } else {
        println!("  VEREDICTO FASE 2: HALLAZGO — desacuerdo entre implementaciones conformes:");
        for d in &dif.desacuerdos {
            println!("    - {} · slh-dsa={} fips205={}", d.descripcion, d.slh_dsa, d.fips205);
        }
    }

    println!("-- FASE 3 (canonicidad): NO APLICA a SLH-DSA --");
    println!(
        "  Una firma SLH-DSA es R‖SIG_FORS‖SIG_HT: concatenación de hashes de longitud fija,"
    );
    println!(
        "  sin enteros empaquetados, hint ni rangos. No hay codificación válida-pero-no-canónica"
    );
    println!(
        "  que perturbar; el barrido de bits (fases 1 y 2) agota la superficie estructural."
    );
}
