# iraca-3

Adversarial and differential verification harness for SLH-DSA-SHA2-256s
(FIPS 205), the NIST post-quantum hash-based signature standard. MIT OR Apache-2.0.  
FIPS 205 · SLH-DSA · hash-based signatures · differential oracle · malleability

**English** · [Español](#español)

---

## The code is not hosted here

Since August 2026 the source of this project **is not hosted on GitHub**, and it
is not distributed through crates.io or any public registry.

This is not abandonment, not an incident, and there was no breach. It is a
decision, and it is worth saying what it rests on. Through 2026 the package
registries and code-hosting platforms were hit by sustained, chained
supply-chain attacks — the Shai-Hulud worm, ChainDrop in August, malicious
extensions that exfiltrated thousands of private repositories. For a
cryptographic verification tool, hosting the source there stopped being a
neutral decision.

**The licence has not changed and the code is still available to anyone who
asks** — delivered with a signature and a checksum, at no cost, with no NDA, no
restriction on what you publish about it, and no expiry.

### Get the source

Request the signed source via **[xiliux.com](https://xiliux.com)**.

---

## What it does

The ecosystem covers **conformance** (FIPS 205 KAT vectors test valid inputs).
What nobody owns is the **adversarial layer**: what does `verify` do with
something that is _not_ a valid signature? A correct `verify` rejects it all;
one that accepts anything is malleability.

Iraca-3 applies the iraca methodology to SLH-DSA-SHA2-256s, the NIST hash-based
signature standard (FIPS 205), across two fully independent Rust implementations:
`slh-dsa` (RustCrypto) and `fips205` (integritychain).

### Phase 1 — abuse of `slh-dsa` (RustCrypto)

1-in-13 bit sweep over the 29,792 B signature, plus structural cases.

| Campaign | Variants tested | Incorrectly accepted |
|---|---|---|
| Malleability (bit-flip sweep, 18,334 variants) | 18,334 | **0** |
| Structural abuse (zeros, ones, length, crossed message/key) | 7 | **0** |

Verdict: **SECO (dry)**.

### Phase 2 — differential `slh-dsa` ↔ `fips205`

Byte-compatible wire format (public key 64 B, signature 29,792 B).

| Control / Campaign | Result |
|---|---|
| Cross A→B (slh-dsa signs → fips205 verifies) | ✅ PASS |
| Cross B→A (fips205 signs → slh-dsa verifies) | ✅ PASS |
| Shared corpus (valid sig + bit-flip sweep + structural + crossed): **18,342 entries** | **0 disagreements** |

The two positive-control crosses make the "0 disagreements" credible.
Verdict: **SECO**.

### Phase 3 — canonicity: does not apply to SLH-DSA

An SLH-DSA signature is `R ‖ SIG_FORS ‖ SIG_HT`: a concatenation of
fixed-length hash outputs, with no packed integers, no hint with ordering rules,
no value ranges. There is no valid-but-non-canonical encoding to perturb — every
byte is a value that `verify` recomputes from scratch.

This structural rigidity is precisely why hash-based signatures are less malleable
than lattice-based ones, and it is an honest finding rather than a gap in coverage.
The bit-flip sweep of phases 1 and 2 exhausts the structural surface.

---

## Español

**[English](#iraca-3)** · Español

Arnés de verificación adversarial y diferencial para SLH-DSA-SHA2-256s
(FIPS 205), la firma hash-based post-cuántica del NIST. MIT OR Apache-2.0.  
FIPS 205 · SLH-DSA · firmas hash-based · oráculo diferencial · maleabilidad

---

### El código no se publica aquí

Desde agosto de 2026, el código de este proyecto **no se aloja en GitHub**, ni
se distribuye por crates.io ni ningún registro público.

No es abandono ni un incidente: es una decisión. A lo largo de 2026 los
registros de paquetes y las plataformas de código han sufrido ataques
encadenados de cadena de suministro —Shai-Hulud, ChainDrop en agosto,
extensiones maliciosas que se llevaron miles de repositorios privados—. Alojar
aquí el código de una herramienta de verificación criptográfica dejó de ser una
decisión neutra.

**La licencia no cambia y el código se sigue entregando a quien lo pida**, con
su firma y su suma de verificación, sin coste, sin NDA, sin restricción sobre lo
que publique y sin caducidad.

### Conseguir el código

Solicite el fuente firmado en **[xiliux.com](https://xiliux.com)**.

---

### Qué hace

El ecosistema cubre la **conformidad** (vectores KAT de FIPS 205). Lo que nadie
tiene como dueño es la capa **adversarial**: qué hace `verify` ante lo que NO es
una firma válida. Un `verify` robusto lo rechaza todo; uno que acepte algo es
maleabilidad.

Iraca-3 aplica la metodología iraca a SLH-DSA-SHA2-256s (FIPS 205) sobre dos
implementaciones Rust completamente independientes: `slh-dsa` (RustCrypto) y
`fips205` (integritychain).

### Fase 1 — abuso de `slh-dsa` (RustCrypto)

| Campaña | Variantes probadas | Aceptadas indebidamente |
|---|---|---|
| Malleability (barrido de bits, 18 334 variantes) | 18 334 | **0** |
| Abuso estructural (ceros, unos, longitud, mensaje/clave cruzados) | 7 | **0** |

**Veredicto: SECO.**

### Fase 2 — diferencial `slh-dsa` ↔ `fips205`

Formato de wire byte-compatible (clave pública 64 B, firma 29 792 B).

| Control / Campaña | Resultado |
|---|---|
| Cruce A→B (slh-dsa firma → fips205 verifica) | ✅ VERDE |
| Cruce B→A (fips205 firma → slh-dsa verifica) | ✅ VERDE |
| Corpus compartido (firma válida + barrido + estructurales + cruzados): **18 342 entradas** | **0 desacuerdos** |

**Veredicto: SECO.**

### Fase 3 — canonicidad: NO APLICA a SLH-DSA

Una firma SLH-DSA es `R ‖ SIG_FORS ‖ SIG_HT`: concatenación de salidas hash de
longitud fija, sin enteros empaquetados, sin hint con reglas de orden, sin rangos.
No existe codificación válida-pero-no-canónica que perturbar —cada byte es un
valor que `verify` recomputa desde cero—. Esta rigidez estructural es justamente
por qué las firmas hash-based son menos maleables que las lattice, y es un
hallazgo honesto, no una fase forzada.

---

*iraca-3* — © 2026 Juan Carlos Isaza. Licence: **MIT OR Apache-2.0**.  
La licencia no cambia: lo que cambia es cómo se entrega el código.
