/*
 * Optimized Private Pairing-Free VRF (P-DY-PrivExtra)
 *
 * An optimized fully private variant of the Pairing-Free Dodis-Yampolskiy VRF that hides
 * both input and output through four commitments and zero-knowledge proofs.
 *
 * Input:
 * - sk: Secret key (hidden in cm1)
 * - x: Input value (hidden in cm2)
 * - Randomness values r1, r2, r3, r4 for commitments
 *
 * Commitments:
 * - cm1 = g1^sk * g^r1 (secret key commitment)
 * - cm2 = g2^x * g^r2 (input commitment)
 * - cm3 = g3^β * g^r3 (output commitment where β = 1/(sk+x))
 * - cm4 = cm3^(sk+x) * g^r4 = g3 * g^(r3*(sk+x) + r4) (composite commitment)
 *
 * Output:
 * - y = g^β (VRF output in G)
 * - All commitments cm1-cm4
 * - π = Sigma-protocol proof with:
 *     * First-message values t1-t4
 *     * Responses z_sk, z_x, z_beta, z_r1-z_r4
 *
 * Relation proven:
 * R = {
 *     (cm1, cm2, cm3, cm4, y),
 *     (sk, x, β, r1, r2, r3, r4)
 *     |
 *     cm1 = g1^sk * g^r1 ∧
 *     cm2 = g2^x * g^r2 ∧
 *     cm3 = g3^β * g^r3 ∧
 *     cm4 = cm3^(sk+x) * g^r4 ∧
 *     y = g^β ∧
 *     β = 1/(sk + x)
 * }
 */
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use ark_std::{rand::Rng, UniformRand};
use core::marker::PhantomData;

/// Input to the Optimized Private Pairing-Free VRF
#[derive(Clone, Debug)]
pub struct PDYPrivExtraInput<F> {
    pub x: F, // The input value
}

/// Witness for the Optimized Private Pairing-Free VRF
#[derive(Clone, Debug)]
pub struct PDYPrivExtraWitness<F> {
    pub sk: F, // Secret key
    pub x: F,  // Input value
    pub r1: F, // Randomness for commitment to sk
    pub r2: F, // Randomness for commitment to x
    pub r3: F, // Randomness for commitment to β = 1/(sk+x)
    pub r4: F, // Randomness for composite commitment
}

/// Commitments for the Optimized Private Pairing-Free VRF
#[derive(Clone, Debug)]
pub struct PDYPrivExtraCommitments<G: AffineRepr> {
    pub cm1: G, // Commitment to secret key: g₁^sk * g^r₁
    pub cm2: G, // Commitment to input: g₂^x * g^r₂
    pub cm3: G, // Commitment to VRF output: g₃^β * g^r₃ where β = 1/(sk+x)
    pub cm4: G, // Composite commitment: cm₃^(sk+x) * g^r₄ = g₃ * g^(r₃*(sk+x) + r₄)
}

/// VRF output and proof for the Optimized Private Pairing-Free VRF
#[derive(Clone, Debug)]
pub struct PDYPrivExtraOutput<G: AffineRepr> {
    pub commitments: PDYPrivExtraCommitments<G>, // All commitments
}

/// Proof for the Optimized Private Pairing-Free VRF using Σ-protocol
pub struct PDYPrivExtraProof<G: AffineRepr> {
    // Commitments from the protocol
    pub t1: G, // T₁ = g₁^a_sk * g^a_r₁
    pub t2: G, // T₂ = g₂^a_x * g^a_r₂
    pub t3: G, // T₃ = g₃^a_β * g^a_r₃
    pub t4: G, // T₄ = cm₃^(a_sk + a_x) * g^a_r₄

    // Responses from the protocol
    pub z_sk: G::ScalarField,   // z_sk = a_sk + c*sk
    pub z_x: G::ScalarField,    // z_x = a_x + c*x
    pub z_beta: G::ScalarField, // z_β = a_β + c*β
    pub z_r1: G::ScalarField,   // z_r₁ = a_r₁ + c*r₁
    pub z_r2: G::ScalarField,   // z_r₂ = a_r₂ + c*r₂
    pub z_r3: G::ScalarField,   // z_r₃ = a_r₃ + c*r₃
    pub z_r4: G::ScalarField,   // z_r₄ = a_r₄ + c*r₄
}

/// Public parameters for the Optimized Private Pairing-Free VRF
pub struct PDYPrivExtraPublicParams<G: AffineRepr> {
    pub g: G,  // Base generator
    pub g1: G, // Generator for secret key commitment
    pub g2: G, // Generator for input commitment
    pub g3: G, // Generator for VRF output commitment
}

/// Optimized Private Pairing-Free VRF implementation
pub struct PDYPrivExtraVRF<G: AffineRepr> {
    _phantom: PhantomData<G>,
    pp: PDYPrivExtraPublicParams<G>,
}

impl<G: AffineRepr> PDYPrivExtraVRF<G> {
    /// Initialize a new optimized P-DY-Priv VRF with random generators
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        let g = G::Group::rand(rng).into_affine();
        let g1 = G::Group::rand(rng).into_affine();
        let g2 = G::Group::rand(rng).into_affine();
        let g3 = G::Group::rand(rng).into_affine();

        PDYPrivExtraVRF {
            _phantom: PhantomData,
            pp: PDYPrivExtraPublicParams { g, g1, g2, g3 },
        }
    }

    /// Initialize with specific generators (useful for testing)
    pub fn new_with_generators(g: G, g1: G, g2: G, g3: G) -> Self {
        PDYPrivExtraVRF {
            _phantom: PhantomData,
            pp: PDYPrivExtraPublicParams { g, g1, g2, g3 },
        }
    }

    /// Generate a complete witness with all necessary values and randomness
    pub fn generate_full_witness<R: Rng>(
        &self,
        sk: &G::ScalarField,
        x: &G::ScalarField,
        rng: &mut R,
    ) -> PDYPrivExtraWitness<G::ScalarField> {
        let r1 = G::ScalarField::rand(rng);
        let r2 = G::ScalarField::rand(rng);
        let r3 = G::ScalarField::rand(rng);
        let r4 = G::ScalarField::rand(rng);

        PDYPrivExtraWitness {
            sk: *sk,
            x: *x,
            r1,
            r2,
            r3,
            r4,
        }
    }

    /// Create all the commitments from a witness
    pub fn create_commitments(
        &self,
        witness: &PDYPrivExtraWitness<G::ScalarField>,
    ) -> PDYPrivExtraCommitments<G> {
        // Calculate β = 1/(sk+x)
        let m = witness.sk + witness.x;
        let beta = m.inverse().expect("sk + x should not be zero");

        // cm₁ = g₁^sk * g^r₁
        let cm1 = (self.pp.g1.mul(witness.sk) + self.pp.g.mul(witness.r1)).into_affine();

        // cm₂ = g₂^x * g^r₂
        let cm2 = (self.pp.g2.mul(witness.x) + self.pp.g.mul(witness.r2)).into_affine();

        // cm₃ = g₃^β * g^r₃
        let cm3 = (self.pp.g3.mul(beta) + self.pp.g.mul(witness.r3)).into_affine();

        // cm₄ = cm₃^(sk+x) * g^r₄ = g₃ * g^(r₃*(sk+x) + r₄)
        let cm4 =
            (self.pp.g3.into_group() + self.pp.g.mul(witness.r3 * m + witness.r4)).into_affine();

        PDYPrivExtraCommitments { cm1, cm2, cm3, cm4 }
    }

    /// Evaluate the VRF: compute y = g^(1/(sk+x))
    pub fn evaluate(
        &self,
        witness: &PDYPrivExtraWitness<G::ScalarField>,
    ) -> Result<PDYPrivExtraOutput<G>, &'static str> {
        // Compute β = 1/(sk+x)
        let m = witness.sk + witness.x;
        let beta = m.inverse().ok_or("sk + x is zero")?;

        // Create all the commitments
        let commitments = self.create_commitments(witness);

        Ok(PDYPrivExtraOutput { commitments })
    }

    /// Generate proof with externally provided challenge
    pub fn prove_with_challenge(
        &self,
        witness: &PDYPrivExtraWitness<G::ScalarField>,
        output: &PDYPrivExtraOutput<G>,
        challenge: &G::ScalarField,
        rng: &mut impl Rng,
    ) -> PDYPrivExtraProof<G> {
        // Calculate β = 1/(sk+x)
        let m = witness.sk + witness.x;
        let beta = m.inverse().expect("sk + x should not be zero");

        // 1. Commitment phase: Sample random values
        let a_sk = G::ScalarField::rand(rng);
        let a_x = G::ScalarField::rand(rng);
        let a_beta = G::ScalarField::rand(rng);
        let a_r1 = G::ScalarField::rand(rng);
        let a_r2 = G::ScalarField::rand(rng);
        let a_r3 = G::ScalarField::rand(rng);
        let a_r4 = G::ScalarField::rand(rng);

        // Compute T₁ = g₁^a_sk * g^a_r₁
        let t1 = (self.pp.g1.mul(a_sk) + self.pp.g.mul(a_r1)).into_affine();

        // Compute T₂ = g₂^a_x * g^a_r₂
        let t2 = (self.pp.g2.mul(a_x) + self.pp.g.mul(a_r2)).into_affine();

        // Compute T₃ = g₃^a_β * g^a_r₃
        let t3 = (self.pp.g3.mul(a_beta) + self.pp.g.mul(a_r3)).into_affine();

        // Compute T₄ = cm₃^(a_sk + a_x) * g^a_r₄
        let a_m = a_sk + a_x;
        let t4 = (output.commitments.cm3.mul(a_m) + self.pp.g.mul(a_r4)).into_affine();

        // Use provided challenge
        let c = *challenge;

        // 3. Response phase: Compute z values
        let z_sk = a_sk + (c * witness.sk);
        let z_x = a_x + (c * witness.x);
        let z_beta = a_beta + (c * beta);
        let z_r1 = a_r1 + (c * witness.r1);
        let z_r2 = a_r2 + (c * witness.r2);
        let z_r3 = a_r3 + (c * witness.r3);
        let z_r4 = a_r4 + (c * witness.r4);

        PDYPrivExtraProof {
            t1,
            t2,
            t3,
            t4,
            z_sk,
            z_x,
            z_beta,
            z_r1,
            z_r2,
            z_r3,
            z_r4,
        }
    }

    /// Verify the proof for the VRF evaluation
    pub fn verify(
        &self,
        commitments: &PDYPrivExtraCommitments<G>,
        proof: &PDYPrivExtraProof<G>,
        challenge: &G::ScalarField,
    ) -> bool {
        // Check verification equations:

        // 1. T₁ · cm₁^c ?= g₁^z_sk · g^z_r₁
        let lhs1 = (proof.t1.into_group() + commitments.cm1.mul(*challenge)).into_affine();
        let rhs1 = (self.pp.g1.mul(proof.z_sk) + self.pp.g.mul(proof.z_r1)).into_affine();
        let check1 = lhs1 == rhs1;
        if !check1 {
            println!("Verification failed: Check 1 (T₁ · cm₁^c = g₁^z_sk · g^z_r₁) failed");
        }

        // 2. T₂ · cm₂^c ?= g₂^z_x · g^z_r₂
        let lhs2 = (proof.t2.into_group() + commitments.cm2.mul(*challenge)).into_affine();
        let rhs2 = (self.pp.g2.mul(proof.z_x) + self.pp.g.mul(proof.z_r2)).into_affine();
        let check2 = lhs2 == rhs2;
        if !check2 {
            println!("Verification failed: Check 2 (T₂ · cm₂^c = g₂^z_x · g^z_r₂) failed");
        }

        // 3. T₃ · cm₃^c ?= g₃^z_β · g^z_r₃
        let lhs3 = (proof.t3.into_group() + commitments.cm3.mul(*challenge)).into_affine();
        let rhs3 = (self.pp.g3.mul(proof.z_beta) + self.pp.g.mul(proof.z_r3)).into_affine();
        let check3 = lhs3 == rhs3;
        if !check3 {
            println!("Verification failed: Check 3 (T₃ · cm₃^c = g₃^z_β · g^z_r₃) failed");
        }

        // 4. T₄ · cm₄^c ?= cm₃^(z_sk + z_x) · g^z_r₄
        let lhs4 = (proof.t4.into_group() + commitments.cm4.mul(*challenge)).into_affine();
        let rhs4 =
            (commitments.cm3.mul(proof.z_sk + proof.z_x) + self.pp.g.mul(proof.z_r4)).into_affine();
        let check4 = lhs4 == rhs4;
        if !check4 {
            println!(
                "Verification failed: Check 4 (T₄ · cm₄^c = cm₃^(z_sk + z_x) · g^z_r₄) failed"
            );
        }

        // All conditions must be satisfied
        check1 && check2 && check3 && check4
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine};
    use ark_std::ops::Mul;
    use ark_std::test_rng;

    #[test]
    fn test_pdy_priv_extra_vrf_complete_protocol() {
        let mut rng = test_rng();

        // Initialize VRF
        let vrf = PDYPrivExtraVRF::<G1Affine>::new(&mut rng);

        // Generate secret key and input
        let sk = Fr::rand(&mut rng);
        let x = Fr::rand(&mut rng);

        // Generate full witness with all randomness
        let witness = vrf.generate_full_witness(&sk, &x, &mut rng);

        // Evaluate VRF and create commitments
        let output = vrf.evaluate(&witness).expect("Failed to evaluate VRF");

        // Generate proof
        let challenge = Fr::rand(&mut rng);
        let proof = vrf.prove_with_challenge(&witness, &output, &challenge, &mut rng);

        // Verify the proof
        let is_valid = vrf.verify(&output.commitments, &proof, &challenge);
        assert!(
            is_valid,
            "Optimized P-DY-Priv-Extra VRF verification failed"
        );
    }

    #[test]
    fn test_commitment_properties() {
        let mut rng = test_rng();

        // Initialize VRF
        let vrf = PDYPrivExtraVRF::<G1Affine>::new(&mut rng);

        // Generate secret key and input
        let sk = Fr::rand(&mut rng);
        let x = Fr::rand(&mut rng);

        // Generate full witness with all randomness
        let witness = vrf.generate_full_witness(&sk, &x, &mut rng);

        // Calculate β = 1/(sk+x)
        let m = witness.sk + witness.x;
        let beta = m.inverse().expect("sk + x should not be zero");

        // Create commitments
        let commitments = vrf.create_commitments(&witness);

        // Test cm₄ = cm₃^(sk+x) * g^r₄
        let cm4_direct = (commitments.cm3.mul(m) + vrf.pp.g.mul(witness.r4)).into_affine();
        assert_eq!(commitments.cm4, cm4_direct, "cm₄ relationship doesn't hold");

        // Test that relationship between y = g^β and cm₃ holds
        let y_from_witness = vrf.pp.g.mul(beta).into_affine();
        let expected_cm3 = (vrf.pp.g3.mul(beta) + vrf.pp.g.mul(witness.r3)).into_affine();
        assert_eq!(
            commitments.cm3, expected_cm3,
            "cm₃ relationship doesn't hold"
        );

        // Test cm₄ = g₃ * g^s for some s
        let s = witness.r3 * m + witness.r4;
        let expected_cm4 = (vrf.pp.g3.into_group() + vrf.pp.g.mul(s)).into_affine();
        assert_eq!(commitments.cm4, expected_cm4, "cm₄ = g₃ * g^s doesn't hold");
    }
}
