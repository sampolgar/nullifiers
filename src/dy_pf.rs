/*
 * Pairing-Free VRF (P-DY) = p_dy.rs
 *
 * A pairing-free adaptation of the Dodis-Yampolskiy VRF that operates in a standard
 * prime-order group under the q-DDHI assumption.
 *
 * Core functions:
 * - VRF.Gen(1^λ): Generates (sk, pk) where sk ∈ Zp*, pk = g^sk
 * - VRF.Eval(sk, x): Computes y = g^(1/(sk+x))
 *
 * Relation proven:
 * R = { (pk, x, y), (sk) | pk = g^sk ∧ y^(sk+x) = g }
 *
 * Verification:
 * - g^z = T1 · (pk · g^x)^c
 * - y^z = T2 · g^c
 *
 * Security properties:
 * - Uniqueness: Computationally enforced via Sigma protocol
 * - Pseudorandomness: Based on q-DDHI assumption
 */

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use ark_std::{rand::Rng, UniformRand};
use core::marker::PhantomData;

/// Input to the Pairing-Free VRF
#[derive(Clone, Debug)]
pub struct DYPFVRFInput<F> {
    pub x: F,
}

/// Public key for the Pairing-Free VRF
#[derive(Clone, Debug)]
pub struct DYPFPublicKey<G: AffineRepr> {
    pub pk: G,
}

/// Secret key for the Pairing-Free VRF
#[derive(Clone, Debug)]
pub struct DYPFSecretKey<F> {
    pub sk: F,
}

/// Output of the Pairing-Free VRF
#[derive(Clone, Debug)]
pub struct DYPFVRFOutput<G: AffineRepr> {
    pub y: G,
}

/// Proof for the Pairing-Free VRF using Σ-protocol
pub struct DYPFVRFProof<G: AffineRepr> {
    pub t1: G,             // T₁ = g^r
    pub t2: G,             // T₂ = y^r
    pub z: G::ScalarField, // z = r + c(sk + x)
}

/// Public parameters for the Pairing-Free VRF
pub struct DYPFVRFPublicParams<G: AffineRepr> {
    pub g: G, // Generator of the prime-order group
}

/// Pairing-Free VRF implementation (P-DY)
pub struct DYPFVRF<G: AffineRepr> {
    _phantom: PhantomData<G>,
    pp: DYPFVRFPublicParams<G>,
}

impl<G: AffineRepr> DYPFVRF<G> {
    /// Initialize a new P-DY VRF with a random generator
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        let g = G::Group::rand(rng).into_affine();
        DYPFVRF {
            _phantom: PhantomData,
            pp: DYPFVRFPublicParams { g },
        }
    }

    /// Initialize with a specific generator (useful for testing)
    pub fn new_with_generator(g: G) -> Self {
        DYPFVRF {
            _phantom: PhantomData,
            pp: DYPFVRFPublicParams { g },
        }
    }

    /// Generate keys: VRF.Gen(1^λ) → (sk, pk)
    /// Sample sk ←$ Z_p*, compute pk = g^sk
    pub fn generate_keys<R: Rng>(
        &self,
        rng: &mut R,
    ) -> (DYPFSecretKey<G::ScalarField>, DYPFPublicKey<G>) {
        let sk = G::ScalarField::rand(rng);
        let pk = self.pp.g.mul(sk).into_affine();
        (DYPFSecretKey { sk }, DYPFPublicKey { pk })
    }

    /// Evaluate: VRF.Eval(sk, x) → y
    /// Compute y = g^(1/(sk+x)) ∈ G
    pub fn evaluate(
        &self,
        input: &DYPFVRFInput<G::ScalarField>,
        sk: &DYPFSecretKey<G::ScalarField>,
    ) -> Result<DYPFVRFOutput<G>, &'static str> {
        // Compute 1/(sk+x)
        let exponent = (sk.sk + input.x).inverse().ok_or("sk + x is zero")?;

        // Compute y = g^(1/(sk+x))
        let y = self.pp.g.mul(exponent).into_affine();

        Ok(DYPFVRFOutput { y })
    }

    /// Prove: VRF.Prove(sk, x) → π
    /// Generate proof π using the Σ-protocol
    pub fn prove<R: Rng>(
        &self,
        input: &DYPFVRFInput<G::ScalarField>,
        sk: &DYPFSecretKey<G::ScalarField>,
        output: &DYPFVRFOutput<G>,
        challenge: &G::ScalarField,
        rng: &mut R,
    ) -> Result<DYPFVRFProof<G>, &'static str> {
        // 1. Commitment: Sample r ←$ Z_p
        let r = G::ScalarField::rand(rng);

        // Compute T₁ = g^r
        let t1 = self.pp.g.mul(r).into_affine();

        // Compute T₂ = y^r
        let t2 = output.y.mul(r).into_affine();

        // 2. Challenge: In interactive setting, verifier would send c

        // 3. Response: Compute z = r + c(sk + x)
        let z = r + *challenge * (sk.sk + input.x);

        Ok(DYPFVRFProof { t1, t2, z })
    }

    /// Verify: VRF.Verify(pk, x, y, π) → {0, 1}
    /// Verify proof using the Σ-protocol verification equations
    pub fn verify(
        &self,
        input: &DYPFVRFInput<G::ScalarField>,
        pk: &DYPFPublicKey<G>,
        output: &DYPFVRFOutput<G>,
        proof: &DYPFVRFProof<G>,
        challenge: &G::ScalarField,
    ) -> bool {
        // Compute g^x
        let g_x = self.pp.g.mul(input.x).into_affine();

        // Compute pk·g^x
        let pk_g_x = (pk.pk.into_group() + g_x.into_group()).into_affine();

        // Compute (pk·g^x)^c
        let pk_g_x_c = pk_g_x.mul(*challenge).into_affine();

        // Compute T₁·(pk·g^x)^c
        let rhs1 = (proof.t1.into_group() + pk_g_x_c.into_group()).into_affine();

        // Compute g^z
        let g_z = self.pp.g.mul(proof.z).into_affine();

        // Compute g^c
        let g_c = self.pp.g.mul(*challenge).into_affine();

        // Compute T₂·g^c
        let rhs2 = (proof.t2.into_group() + g_c.into_group()).into_affine();

        // Compute y^z
        let y_z = output.y.mul(proof.z).into_affine();

        // Check: g^z = T₁·(pk·g^x)^c and y^z = T₂·g^c
        g_z == rhs1 && y_z == rhs2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine};
    use ark_std::test_rng;

    #[test]
    fn test_pdyvrf_complete_protocol() {
        let mut rng = test_rng();

        // Initialize VRF
        let vrf = DYPFVRF::<G1Affine>::new(&mut rng);

        // Generate keys
        let (sk, pk) = vrf.generate_keys(&mut rng);

        // Create input
        let input = DYPFVRFInput {
            x: Fr::rand(&mut rng),
        };

        // Generate VRF output
        let output = vrf.evaluate(&input, &sk).expect("Failed to evaluate VRF");

        let challenge = Fr::rand(&mut rng);

        // Generate proof
        let proof = vrf
            .prove(&input, &sk, &output, &challenge, &mut rng)
            .expect("Failed to generate proof");

        // Verify
        let is_valid = vrf.verify(&input, &pk, &output, &proof, &challenge);
        assert!(is_valid, "P-DY VRF verification failed");
    }
}
