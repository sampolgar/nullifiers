/*
 * Dodis-Yampolskiy VRF (DY-VRF)
 *
 * Original VRF construction operating in a bilinear group setting under the q-DBDHI assumption.
 *
 * Core functions:
 * - VRF.Gen(1^λ): Generates (sk, pk) where sk ∈ Zp*, pk = g^sk
 * - VRF.Eval(sk, x): Computes y = e(g, g)^(1/(sk+x)) ∈ GT
 * - VRF.Prove(sk, x): Produces π = g^(1/(sk+x)) ∈ G
 *
 * Verification:
 * - e(g^x · pk, π) = e(g, g)  (Proof correctness)
 * - y = e(g, π)  (Output consistency)
 *
 * Security properties:
 * - Information-theoretic uniqueness: Enforced by pairing properties
 * - Pseudorandomness: Based on q-DBDHI assumption
 * - Efficient verification: Uses bilinear pairing for direct checking
 */
use crate::pairing::create_check;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::Field;
use ark_std::{
    ops::{Add, Mul, Neg},
    rand::Rng,
    One, UniformRand,
};
use core::marker::PhantomData;

/// Input to the Dodis-Yampolskiy VRF
#[derive(Clone, Debug)]
pub struct DYVRFInput<E: Pairing> {
    pub x: E::ScalarField,
}

/// Public key for the Dodis-Yampolskiy VRF
#[derive(Clone, Debug)]
pub struct DYPublicKey<E: Pairing> {
    pub pk: E::G1Affine,
}

/// Secret key for the Dodis-Yampolskiy VRF
#[derive(Clone, Debug)]
pub struct DYSecretKey<E: Pairing> {
    pub sk: E::ScalarField,
}

/// Output of the Dodis-Yampolskiy VRF, including the value y and proof π
#[derive(Clone, Debug)]
pub struct DYVRFOutput<E: Pairing> {
    pub y: E::TargetField,
    pub pi: E::G2Affine,
}

/// Public parameters for the Dodis-Yampolskiy VRF
pub struct DYVRFPublicParams<E: Pairing> {
    pub g1: E::G1Affine, // Generator g of G1
    pub g2: E::G2Affine, // Generator g̃ of G2
}

/// Dodis-Yampolskiy VRF implementation
pub struct DYVRF<E: Pairing> {
    _phantom: PhantomData<E>,
    pp: DYVRFPublicParams<E>,
}

impl<E: Pairing> DYVRF<E> {
    /// Initialize a new DY-VRF with random generators
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        let g1 = E::G1Affine::rand(rng);
        let g2 = E::G2Affine::rand(rng);
        DYVRF {
            _phantom: PhantomData,
            pp: DYVRFPublicParams { g1, g2 },
        }
    }

    /// Initialize with specific generators (useful for testing)
    pub fn new_with_generators(g1: E::G1Affine, g2: E::G2Affine) -> Self {
        DYVRF {
            _phantom: PhantomData,
            pp: DYVRFPublicParams { g1, g2 },
        }
    }

    /// Generate keys: VRF.Gen(1^λ) → (sk, pk)
    /// Sample sk ←$ Z_p*, compute pk = g^sk ∈ G1
    pub fn generate_keys<R: Rng>(&self, rng: &mut R) -> (DYSecretKey<E>, DYPublicKey<E>) {
        let sk = E::ScalarField::rand(rng);
        let pk = self.pp.g1.mul(sk).into_affine();
        (DYSecretKey { sk }, DYPublicKey { pk })
    }

    /// Evaluate and Prove:
    /// VRF.Eval(sk, x) → y: Compute y = e(g,g̃)^(1/(sk+x)) ∈ GT
    /// VRF.Prove(sk, x) → π: Compute proof π = g̃^(1/(sk+x)) ∈ G2
    pub fn evaluate(
        &self,
        input: &DYVRFInput<E>,
        sk: &DYSecretKey<E>,
    ) -> Result<DYVRFOutput<E>, &'static str> {
        // Compute 1/(sk+x)
        let exponent = (sk.sk + input.x).inverse().ok_or("sk + x is zero")?;

        // Compute π = g̃^(1/(sk+x))
        let pi = self.pp.g2.mul(exponent).into_affine();

        // Compute y = e(g, π)
        let y = E::pairing(self.pp.g1, pi).0;

        Ok(DYVRFOutput { y, pi })
    }

    /// Verify - Direct method using GT point equality
    /// VRF.Vfy(pk, x, y, π) → {0, 1}: Verify two equations:
    /// 1. e(g^x · pk, π) = e(g, g̃)
    /// 2. y = e(g, π)
    pub fn verify_direct(
        &self,
        input: &DYVRFInput<E>,
        pk: &DYPublicKey<E>,
        output: &DYVRFOutput<E>,
    ) -> bool {
        // Compute g^x
        let g_x = self.pp.g1.mul(input.x).into_affine();
        // Compute g^x · pk
        let g_x_pk = (g_x.into_group() + pk.pk.into_group()).into_affine();

        // Equation 1: e(g^x · pk, π) = e(g, g̃)
        let lhs1 = E::pairing(g_x_pk, output.pi);
        let rhs1 = E::pairing(self.pp.g1, self.pp.g2);

        // Equation 2: y = e(g, π)
        let lhs2 = output.y;
        let rhs2 = E::pairing(self.pp.g1, output.pi).0;

        lhs1 == rhs1 && lhs2 == rhs2
    }

    /// Verify - Optimized method using pairing checker
    pub fn verify_optimized(
        &self,
        input: &DYVRFInput<E>,
        pk: &DYPublicKey<E>,
        output: &DYVRFOutput<E>,
    ) -> bool {
        // First, verify y = e(g, π)
        let g_x = self.pp.g1.mul(input.x).into_affine();
        let g_x_pk = (g_x.into_group() + pk.pk.into_group()).into_affine();
        let neg_g1 = self.pp.g1.into_group().neg().into_affine();
        let neg_g2 = self.pp.g2.into_group().neg().into_affine();

        // Create a check for: e(-g, π) \cdot e(g^x · pk, π) \cdot e(g, -g̃) = 1/y
        // Equivalent to: y \cdot e(-g, π) \cdot e(g^x · pk, π) \cdot e(g, -g̃) = 1
        let inv_y = output.y.inverse().unwrap_or_else(|| E::TargetField::one());

        let check = create_check::<E>(
            &[
                (&neg_g1, &output.pi),
                (&g_x_pk, &output.pi),
                (&self.pp.g1, &neg_g2),
            ],
            Some(&inv_y),
        );

        check.verify()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_std::test_rng;

    #[test]
    fn test_dyvrf_direct_verification() {
        let mut rng = test_rng();

        // Initialize VRF
        let vrf = DYVRF::<Bls12_381>::new(&mut rng);

        // Generate keys
        let (sk, pk) = vrf.generate_keys(&mut rng);

        // Create input
        let input = DYVRFInput {
            x: <Bls12_381 as Pairing>::ScalarField::rand(&mut rng),
        };

        // Generate VRF output
        let output = vrf.evaluate(&input, &sk).expect("Failed to evaluate VRF");

        // Verify using direct method
        let is_valid = vrf.verify_direct(&input, &pk, &output);
        assert!(is_valid, "DY-VRF direct verification failed");
    }

    #[test]
    fn test_dyvrf_optimized_verification() {
        let mut rng = test_rng();

        // Initialize VRF
        let vrf = DYVRF::<Bls12_381>::new(&mut rng);

        // Generate keys
        let (sk, pk) = vrf.generate_keys(&mut rng);

        // Create input
        let input = DYVRFInput {
            x: <Bls12_381 as Pairing>::ScalarField::rand(&mut rng),
        };

        // Generate VRF output
        let output = vrf.evaluate(&input, &sk).expect("Failed to evaluate VRF");

        // Verify using optimized method
        let is_valid = vrf.verify_optimized(&input, &pk, &output);
        assert!(is_valid, "DY-VRF optimized verification failed");
    }
}
