/*
 * UTT-based Private Dodis-Yampolskiy Verifiable Random Function (VRF)
 *
 * This implementation offers a privacy-enhanced variant of the Dodis-Yampolskiy VRF,
 * inspired by the "Untraceable Decentralized eCash" paper.
 *
 * Input:
 * - ccm = g1^id_master * g2^ctx * g^r (context commitment)
 * - rcm = g1^id_master * g6^k_master * g^a_prime (registration commitment)
 *
 * Output:
 * - nullif = h^(1/(k_master+ctx)) (nullifier in G₁)
 * - vk = h̃^(k_master+ctx)·w̃^t (verification key in G₂)
 * - y = e(nullif, w̃)^t (VRF output in GT)
 * - π = complex zero-knowledge proof (x1, x3, x4, x5, responses)
 *
 * Verification equation:
 * - e(nullif, vk) = e(h, h̃)·y
 * - proof verifies consistency
 *
 * Relation proven:
 * R = {
 *     (ccm, rcm, nullif, vk, y),
 *     (id_master, ctx, k_master, r, a_prime, t)
 *     |
 *     ccm = g1^id_master * g2^ctx * g^r ∧
 *     rcm = g1^id_master * g6^k_master * g^a_prime ∧
 *     nullif = h^(1/(k_master+ctx)) ∧
 *     vk = h̃^(k_master+ctx) * w̃^t ∧
 *     y = e(nullif, w̃)^t
 * }
 *
 *
 * Security properties:
 * - Input privacy: Context values remain hidden in commitments
 * - Output privacy: Values randomized with t while preserving verifiability
 * - Uniqueness: Same context+key always produces identical nullifier
 *
 */
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, UniformRand};
use ark_std::{
    ops::{Add, Mul, Neg},
    rand::Rng,
    One, Zero,
};
use core::marker::PhantomData;

/// Input to the UTT-based Dodis-Yampolskiy VRF
#[derive(Clone, Debug)]
pub struct DYPrivInput<E: Pairing> {
    pub ctx: E::ScalarField, // Context/message to evaluate
}

/// Public key for the UTT-based Dodis-Yampolskiy VRF
#[derive(Clone, Debug)]
pub struct DYPrivPublicKey<E: Pairing> {
    pub ccm: E::G1Affine, // Commitment to context
    pub vk: E::G2Affine,  // Verification key
}

/// Secret key for the UTT-based Dodis-Yampolskiy VRF
#[derive(Clone, Debug)]
pub struct DYPrivSecretKey<E: Pairing> {
    pub k_master: E::ScalarField,  // Master key
    pub id_master: E::ScalarField, // Master identity
    pub t: E::ScalarField,         // Trapdoor value
    pub r: E::ScalarField,         // Randomness for commitment
    pub a_prime: E::ScalarField,   // Additional randomness
}

/// Output of the UTT-based Dodis-Yampolskiy VRF
#[derive(Clone, Debug)]
pub struct DYPrivOutput<E: Pairing> {
    pub y: PairingOutput<E>, // VRF output in target field
}

/// Proof for the UTT-based Dodis-Yampolskiy VRF
#[derive(Clone, Debug)]
pub struct DYPrivProof<E: Pairing> {
    pub nullif: E::G1Affine,  // The nullifier value
    pub ccm: E::G1Affine,     // Context commitment
    pub rcm: E::G1Affine,     // Registration commitment
    pub vk: E::G2Affine,      // Verification key
    pub y: PairingOutput<E>,  // VRF output
    pub x1: E::G1Affine,      // Proof commitment 1
    pub x3: E::G1Affine,      // Proof commitment 3
    pub x4: E::G2Affine,      // Proof commitment 4
    pub x5: PairingOutput<E>, // Proof commitment 5
    pub a1: E::ScalarField,   // Response 1
    pub a2: E::ScalarField,   // Response 2
    pub a4: E::ScalarField,   // Response 4
    pub a6: E::ScalarField,   // Response 6
    pub a7: E::ScalarField,   // Response 7
    pub a8: E::ScalarField,   // Response 8
    pub c: E::ScalarField,    // Challenge value
}

/// Public parameters for the UTT-based Dodis-Yampolskiy VRF
#[derive(Clone)]
pub struct DYPrivPublicParams<E: Pairing> {
    pub g: E::G1Affine,       // Generator of G1
    pub g1: E::G1Affine,      // Commitment base for identity
    pub g2: E::G1Affine,      // Commitment base for context
    pub g6: E::G1Affine,      // Commitment base for key
    pub h: E::G1Affine,       // Structured base in G1
    pub h_tilde: E::G2Affine, // Structured base in G2 (paired with h)
    pub w_tilde: E::G2Affine, // Additional G2 base
}

/// UTT-based Dodis-Yampolskiy VRF implementation
pub struct DYPrivVRF<E: Pairing> {
    _phantom: PhantomData<E>,
    pub pp: DYPrivPublicParams<E>,
}

impl<E: Pairing> DYPrivVRF<E> {
    /// Initialize a new DY-UTT VRF with random generators
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        let g = E::G1Affine::rand(rng);
        let g1 = E::G1Affine::rand(rng);
        let g2 = E::G1Affine::rand(rng);
        let g6 = E::G1Affine::rand(rng);

        // Create structured bases that share the same discrete log
        let h_scalar = E::ScalarField::rand(rng);
        let h = E::G1Affine::generator().mul(h_scalar).into_affine();
        let h_tilde = E::G2Affine::generator().mul(h_scalar).into_affine();

        let w_tilde = E::G2Affine::rand(rng);

        DYPrivVRF {
            _phantom: PhantomData,
            pp: DYPrivPublicParams {
                g,
                g1,
                g2,
                g6,
                h,
                h_tilde,
                w_tilde,
            },
        }
    }

    /// Initialize with specific parameters (useful for testing)
    pub fn new_with_params(pp: DYPrivPublicParams<E>) -> Self {
        DYPrivVRF {
            _phantom: PhantomData,
            pp,
        }
    }

    /// Get commitment bases from public parameters
    pub fn get_ccm_bases(&self) -> Vec<E::G1Affine> {
        vec![self.pp.g1, self.pp.g2, self.pp.g]
    }

    pub fn get_rcm_bases(&self) -> Vec<E::G1Affine> {
        vec![self.pp.g1, self.pp.g6, self.pp.g]
    }

    /// Generate keys: VRF.Gen(1^λ) → (sk, pk)
    pub fn generate_keys<R: Rng>(&self, rng: &mut R) -> (DYPrivSecretKey<E>, DYPrivPublicKey<E>) {
        let k_master = E::ScalarField::rand(rng);
        let id_master = E::ScalarField::rand(rng);
        let t = E::ScalarField::rand(rng);
        let r = E::ScalarField::rand(rng);
        let a_prime = E::ScalarField::rand(rng);

        // Create context commitment (initially empty)
        let ccm =
            (self.pp.g1.mul(id_master) + self.pp.g2.mul(E::ScalarField::zero()) + self.pp.g.mul(r))
                .into_affine();

        // Create verification key
        let vk = (self.pp.h_tilde.mul(k_master) + self.pp.w_tilde.mul(t)).into_affine();

        (
            DYPrivSecretKey {
                k_master,
                id_master,
                t,
                r,
                a_prime,
            },
            DYPrivPublicKey { ccm, vk },
        )
    }

    /// Evaluate: VRF.Eval(sk, x) → (y, π)
    pub fn evaluate<R: Rng>(
        &self,
        sk: &DYPrivSecretKey<E>,
        input: &DYPrivInput<E>,
        rng: &mut R,
    ) -> Result<(DYPrivProof<E>, DYPrivOutput<E>), &'static str> {
        // Compute key + context
        let exponent = sk.k_master + input.ctx;
        if exponent.is_zero() {
            return Err("k_master + ctx is zero");
        }

        // Compute inverse for nullifier
        let exponent_inv = exponent.inverse().unwrap();

        // Compute nullifier as h^(1/(k+ctx))
        let nullif = self.pp.h.mul(exponent_inv).into_affine();

        // Compute verification key
        let vk = (self.pp.h_tilde.mul(exponent) + self.pp.w_tilde.mul(sk.t)).into_affine();

        // Compute output via pairing
        let q = E::pairing(nullif, self.pp.w_tilde);
        let y = q * sk.t; // Direct scalar multiplication as in original code

        // Create commitments
        let ccm = (self.pp.g1.mul(sk.id_master) + self.pp.g2.mul(input.ctx) + self.pp.g.mul(sk.r))
            .into_affine();
        let rcm = (self.pp.g1.mul(sk.id_master)
            + self.pp.g6.mul(sk.k_master)
            + self.pp.g.mul(sk.a_prime))
        .into_affine();

        // Generate proof
        let x1 = E::ScalarField::rand(rng);
        let x2 = E::ScalarField::rand(rng);
        let x4 = E::ScalarField::rand(rng);
        let x6 = E::ScalarField::rand(rng);
        let x7 = E::ScalarField::rand(rng);
        let x8 = E::ScalarField::rand(rng);

        let x1_point = (self.pp.g1.mul(x1) + self.pp.g2.mul(x2) + self.pp.g.mul(x4)).into_affine();
        let x3_point = (self.pp.g1.mul(x1) + self.pp.g6.mul(x6) + self.pp.g.mul(x7)).into_affine();
        let x4_point =
            (self.pp.h_tilde.mul(x6) + self.pp.h_tilde.mul(x2) + self.pp.w_tilde.mul(x8))
                .into_affine();
        let x5_point = q * x8; // Direct scalar multiplication as in original code

        // In a real implementation, we would compute the challenge as a hash of public values
        let c = E::ScalarField::rand(rng);

        // Compute responses
        let a1 = x1 + c * sk.id_master;
        let a2 = x2 + c * input.ctx;
        let a4 = x4 + c * sk.r;
        let a6 = x7 + c * sk.a_prime;
        let a7 = x6 + c * sk.k_master;
        let a8 = x8 + c * sk.t;

        let proof = DYPrivProof {
            nullif,
            ccm,
            rcm,
            vk,
            y,
            x1: x1_point,
            x3: x3_point,
            x4: x4_point,
            x5: x5_point,
            a1,
            a2,
            a4,
            a6,
            a7,
            a8,
            c,
        };

        let output = DYPrivOutput { y };

        Ok((proof, output))
    }

    /// Verify: VRF.Verify(pk, x, y, π) → {0, 1}
    pub fn verify(
        &self,
        _pk: &DYPrivPublicKey<E>,
        _input: &DYPrivInput<E>,
        proof: &DYPrivProof<E>,
    ) -> bool {
        // Verify pairing equation: e(nullifier, vk) = e(h, h_tilde) + y
        let lhs_pairing = E::pairing(proof.nullif, proof.vk);
        let rhs_pairing = E::pairing(self.pp.h, self.pp.h_tilde) + proof.y;
        if lhs_pairing != rhs_pairing {
            return false;
        }

        // Verify context commitment: ccm * c + X1 = g1^a1 * g2^a2 * g^a4
        let lhs_ccm = (proof.ccm.mul(proof.c) + proof.x1).into_affine();
        let rhs_ccm =
            (self.pp.g1.mul(proof.a1) + self.pp.g2.mul(proof.a2) + self.pp.g.mul(proof.a4))
                .into_affine();
        if lhs_ccm != rhs_ccm {
            return false;
        }

        // Verify relation commitment: rcm * c + X3 = g1^a1 * g6^a7 * g^a6
        let lhs_rcm = (proof.rcm.mul(proof.c) + proof.x3).into_affine();
        let rhs_rcm =
            (self.pp.g1.mul(proof.a1) + self.pp.g6.mul(proof.a7) + self.pp.g.mul(proof.a6))
                .into_affine();
        if lhs_rcm != rhs_rcm {
            return false;
        }

        // Verify verification key: vk * c + X4 = h_tilde^a7 * h_tilde^a2 * w_tilde^a8
        let lhs_vk = (proof.vk.mul(proof.c) + proof.x4).into_affine();
        let rhs_vk = (self.pp.h_tilde.mul(proof.a7)
            + self.pp.h_tilde.mul(proof.a2)
            + self.pp.w_tilde.mul(proof.a8))
        .into_affine();
        if lhs_vk != rhs_vk {
            return false;
        }

        // Verify y: y * c + X5 = q * a8 where q = e(nullifier, w_tilde)
        let q = E::pairing(proof.nullif, self.pp.w_tilde);
        let lhs_y = proof.y.mul(proof.c) + proof.x5; // Using .mul() and + as in original code
        let rhs_y = q * proof.a8; // Direct scalar multiplication as in original code

        lhs_y == rhs_y
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_std::test_rng;

    #[test]
    fn test_dyutt_vrf() {
        // Initialize a deterministic RNG for reproducibility
        let mut rng = test_rng();

        // Set up VRF with public parameters
        let vrf = DYPrivVRF::<Bls12_381>::new(&mut rng);

        // Generate keys
        let (sk, pk) = vrf.generate_keys(&mut rng);

        // Create input
        let input = DYPrivInput {
            ctx: <Bls12_381 as Pairing>::ScalarField::rand(&mut rng),
        };

        // Evaluate the VRF
        let (proof, _output) = vrf
            .evaluate(&sk, &input, &mut rng)
            .expect("VRF evaluation failed");

        // Verify the proof
        assert!(
            vrf.verify(&pk, &input, &proof),
            "DY-UTT VRF verification failed"
        );
    }
}
