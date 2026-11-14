# Iraca-3 — verificación adversarial y diferencial de SLH-DSA (FIPS 205)

Hermana de **Iraca** (leanSig, XMSS) e **Iraca-2** (ML-DSA, lattice). Misma tesis:
el ecosistema cubre la **conformidad** (vectores KAT, entradas válidas); lo que nadie
tiene como dueño es la capa **adversarial** —qué hace `verify` ante lo que NO es una
firma válida—. Un `verify` robusto lo rechaza todo; una que acepte algo es
maleabilidad.

Objetivo: **SLH-DSA-SHA2-256s**, la firma hash-based del NIST, en las dos
implementaciones Rust independientes y conformes de FIPS 205.

## Qué mira, y por qué es el hueco

- **Conformidad** (cubierto por otros): los KAT de FIPS 205, entradas válidas.
- **Iraca-3** (el hueco): abuso de una implementación (fase 1) y **desacuerdo**
  entre dos (fase 2).

El foso: nuestro stack (**quipu**, feature `slh`, la firma triple del perito en
medico) usa **SLH-DSA-SHA2-256s vía el crate `fips205`**. El diferencial cruza esa
implementación con `slh-dsa` de RustCrypto **en ese mismo parámetro**: un desacuerdo
sería un matiz de la implementación que nuestro producto consume, no académico.

## Fase 1 — abuso de `slh-dsa` (RustCrypto)

`cargo run --release --example medir`.

Barrido de bit-flips (1 de cada 13 bits sobre los 29792 B de la firma) + casos
estructurales (ceros, unos, longitud, mensaje/clave cruzados).

| campaña | resultado |
|---|---|
| malleability, **18334** variantes de 1 bit | **0 aceptadas** |
| abuso estructural, 7 casos | **0 aceptadas** |

Control positivo D33 (`la_firma_valida_verifica`) y su pareja (`un_bit_cambiado_no_verifica`).
**Veredicto: SECO.**

## Fase 2 — diferencial `slh-dsa` ↔ `fips205` (la de quipu)

Segunda implementación: `fips205` 0.4.1 (integritychain), código totalmente distinto.
Byte-compatibles por FIPS 205 (pk 64 B, firma 29792 B, contexto vacío, mismo framing
`0x00‖len(ctx)=0‖msg` —verificado en la fuente—).

| control / campaña | resultado |
|---|---|
| cruce A→B (slh-dsa firma → fips205 verifica) | **VERDE** |
| cruce B→A (fips205 firma → slh-dsa verifica) | **VERDE** |
| corpus compartido (firma válida + barrido + estructurales + cruzados): **18342** entradas | **0 desacuerdos** |

Los dos cruces en verde (D30) hacen creíble el «0 desacuerdos»: las dos se entienden
en lo válido **y** coinciden en lo que rechazan. Pareja D33
(`un_desacuerdo_fabricado_se_detecta`). **Veredicto: SECO.**

## Fase 3 — canonicidad: NO APLICA a SLH-DSA

A diferencia de ML-DSA (Iraca-2, donde el *hint* y el rango de `z` daban terreno
estructural), una firma SLH-DSA es `R ‖ SIG_FORS ‖ SIG_HT`: concatenación de salidas
hash de **longitud fija**, sin enteros empaquetados, sin *hint* con reglas de orden,
sin rangos. **No existe codificación válida-pero-no-canónica** que perturbar —cada
byte es un valor que `verify` recomputa—. El barrido de bits de las fases 1 y 2 agota
la superficie estructural. Esa rigidez es justamente por qué las firmas hash-based
son menos maleables que las lattice, y es un hallazgo honesto, no una fase forzada.

## Conclusión

Las dos implementaciones Rust de SLH-DSA-SHA2-256s están **bien cerradas** ante abuso
y diferencial; en particular `fips205`, la que consume quipu, no discrepa de la
implementación independiente de RustCrypto en ninguna de las 18342 entradas. Como en
Iraca-2, el hallazgo pagable —si existe en SLH-DSA— no vive en la firma de una
implementación madura, sino en otra menos madura o en la **capa de uso**
(contexto/dominio/nonce de un protocolo que la consuma).

## Licencia

MIT OR Apache-2.0 (ver `LICENSE-MIT`, `LICENSE-APACHE`, `NOTICE`).
