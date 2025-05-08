use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_std::{rand::Rng, test_rng};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use nullifiers::{
    dy::{DYPublicKey, DYSecretKey, DYVRFInput, DYVRF},
    dy_pf::{DYPFPublicKey, DYPFSecretKey, DYPFVRFInput, DYPFVRF},
    dy_pf_priv::{
        DYPFPrivPublicKey, DYPFPrivSecretKey, DYPFPrivVRF, DYPFPrivVRFInput, DYPFPrivVRFWitness,
    },
    dy_pf_priv_commited_output::{PDYPrivExtraVRF, PDYPrivExtraWitness},
    dy_priv::{DYPrivInput, DYPrivPublicKey, DYPrivSecretKey, DYPrivVRF},
};

// Number of runs for each benchmark - change to 10 for quicker testing
const NUM_RUNS: usize = 100;

fn bench_dy_vrf(c: &mut Criterion) {
    let mut group = c.benchmark_group("dy");
    let mut rng = test_rng();

    // Initialize VRF
    let vrf = DYVRF::<Bls12_381>::new(&mut rng);

    // Generate keys
    let (sk, pk) = vrf.generate_keys(&mut rng);

    // Precompute random inputs for eval_prove
    let eval_inputs: Vec<_> = (0..NUM_RUNS)
        .map(|_| DYVRFInput {
            x: <Bls12_381 as Pairing>::ScalarField::rand(&mut rng),
        })
        .collect();
    let mut eval_idx = 0;

    // Benchmark Eval + Prove
    group.bench_function("eval_prove", |b| {
        b.iter(|| {
            // Use a different input each time
            let input = &eval_inputs[eval_idx % NUM_RUNS];
            eval_idx += 1;
            let _output = vrf.evaluate(input, &sk).expect("Failed to evaluate VRF");
        })
    });

    // Pre-compute some outputs for verification benchmarks
    let inputs: Vec<_> = (0..NUM_RUNS)
        .map(|_| DYVRFInput {
            x: <Bls12_381 as Pairing>::ScalarField::rand(&mut rng),
        })
        .collect();

    let outputs: Vec<_> = inputs
        .iter()
        .map(|input| vrf.evaluate(input, &sk).expect("Failed to evaluate VRF"))
        .collect();

    let mut verify_idx = 0;
    // Benchmark verify
    group.bench_function("verify", |b| {
        b.iter(|| {
            let i = verify_idx % NUM_RUNS;
            verify_idx += 1;
            let is_valid = vrf.verify_direct(&inputs[i], &pk, &outputs[i]);
            assert!(is_valid, "DY-VRF verification failed");
        })
    });

    let mut verify_opt_idx = 0;
    // Benchmark verify (Optimized)
    group.bench_function("verify_optimized", |b| {
        b.iter(|| {
            let i = verify_opt_idx % NUM_RUNS;
            verify_opt_idx += 1;
            let is_valid = vrf.verify_optimized(&inputs[i], &pk, &outputs[i]);
            assert!(is_valid, "DY-VRF optimized verification failed");
        })
    });

    group.finish();
}

fn bench_dy_pf_vrf(c: &mut Criterion) {
    let mut group = c.benchmark_group("dy_pf");
    let mut rng = test_rng();

    // Initialize VRF
    let vrf = DYPFVRF::<G1Affine>::new(&mut rng);

    // Generate keys
    let (sk, pk) = vrf.generate_keys(&mut rng);

    // Pre-compute challenges for consistent testing
    let challenges: Vec<_> = (0..NUM_RUNS).map(|_| Fr::rand(&mut rng)).collect();

    // Precompute random inputs for eval_prove
    let eval_inputs: Vec<_> = (0..NUM_RUNS)
        .map(|_| DYPFVRFInput {
            x: Fr::rand(&mut rng),
        })
        .collect();
    let mut eval_idx = 0;

    // Benchmark eval_prove
    group.bench_function("eval_prove", |b| {
        b.iter(|| {
            let i = eval_idx % NUM_RUNS;
            eval_idx += 1;
            let input = &eval_inputs[i];
            let output = vrf.evaluate(input, &sk).expect("Failed to evaluate VRF");
            let _proof = vrf
                .prove(input, &sk, &output, &challenges[i], &mut rng)
                .expect("Failed to generate proof");
        })
    });

    // Pre-compute inputs, outputs, and proofs for verification benchmarks
    let inputs: Vec<_> = (0..NUM_RUNS)
        .map(|_| DYPFVRFInput {
            x: Fr::rand(&mut rng),
        })
        .collect();

    let outputs: Vec<_> = inputs
        .iter()
        .map(|input| vrf.evaluate(input, &sk).expect("Failed to evaluate VRF"))
        .collect();

    let proofs: Vec<_> = (0..NUM_RUNS)
        .map(|i| {
            vrf.prove(&inputs[i], &sk, &outputs[i], &challenges[i], &mut rng)
                .expect("Failed to generate proof")
        })
        .collect();

    let mut verify_idx = 0;
    // Benchmark verify
    group.bench_function("verify", |b| {
        b.iter(|| {
            let i = verify_idx % NUM_RUNS;
            verify_idx += 1;
            let is_valid = vrf.verify(&inputs[i], &pk, &outputs[i], &proofs[i], &challenges[i]);
            assert!(is_valid, "P-DY-VRF verification failed");
        })
    });

    group.finish();
}

fn bench_dy_pf_priv_vrf(c: &mut Criterion) {
    let mut group = c.benchmark_group("dy_pf_priv");
    let mut rng = test_rng();

    // Initialize VRF
    let vrf = DYPFPrivVRF::<G1Affine>::new(&mut rng);

    // Generate keys
    let (sk, mut pk) = vrf.generate_keys(&mut rng);

    // Pre-compute challenges for consistent testing
    let challenges: Vec<_> = (0..NUM_RUNS).map(|_| Fr::rand(&mut rng)).collect();

    // Precompute random inputs for eval_prove
    let eval_inputs: Vec<_> = (0..NUM_RUNS).map(|_| Fr::rand(&mut rng)).collect();
    let mut eval_idx = 0;

    // Benchmark eval_prove
    group.bench_function("eval_prove", |b| {
        b.iter(|| {
            let i = eval_idx % NUM_RUNS;
            eval_idx += 1;
            let x = eval_inputs[i];
            let (input, cm_x) = vrf.commit_to_input(&x, &mut rng);
            let mut pk_clone = DYPFPrivPublicKey {
                cm_sk: pk.cm_sk.clone(),
                cm_x,
            };
            let witness = DYPFPrivVRFWitness {
                sk: sk.sk,
                r_sk: sk.r_sk,
                x: input.x,
                r_x: input.r_x,
            };
            let output = vrf.evaluate(&witness).expect("Failed to evaluate VRF");
            let _proof = vrf.prove_with_challenge(&witness, &output, &challenges[i], &mut rng);
        })
    });

    // Create a tuple of (witness, commitment) to ensure they match
    let witnesses_and_commitments: Vec<(DYPFPrivVRFWitness<Fr>, G1Affine)> = (0..NUM_RUNS)
        .map(|_| {
            let x = Fr::rand(&mut rng);
            let (input, cm_x) = vrf.commit_to_input(&x, &mut rng);
            let witness = DYPFPrivVRFWitness {
                sk: sk.sk,
                r_sk: sk.r_sk,
                x: input.x,
                r_x: input.r_x,
            };
            (witness, cm_x)
        })
        .collect();

    let witnesses: Vec<_> = witnesses_and_commitments
        .iter()
        .map(|(w, _)| w.clone())
        .collect();
    let pks: Vec<DYPFPrivPublicKey<G1Affine>> = witnesses_and_commitments
        .iter()
        .map(|(_, cm_x)| DYPFPrivPublicKey {
            cm_sk: pk.cm_sk.clone(),
            cm_x: *cm_x,
        })
        .collect();

    let outputs: Vec<_> = witnesses
        .iter()
        .map(|witness| vrf.evaluate(witness).expect("Failed to evaluate VRF"))
        .collect();

    let proofs: Vec<_> = (0..NUM_RUNS)
        .map(|i| vrf.prove_with_challenge(&witnesses[i], &outputs[i], &challenges[i], &mut rng))
        .collect();

    let mut verify_idx = 0;
    // Now verification should pass
    group.bench_function("Verify", |b| {
        b.iter(|| {
            let i = verify_idx % NUM_RUNS;
            verify_idx += 1;
            let is_valid = vrf.verify(&pks[i], &outputs[i], &proofs[i], &challenges[i]);
            assert!(is_valid, "P-DY-Priv-VRF verification failed");
        })
    });

    group.finish();
}

fn bench_dy_pf_priv_committed_output_vrf(c: &mut Criterion) {
    let mut group = c.benchmark_group("dy_pf_priv_commited_output");
    let mut rng = test_rng();

    // Initialize VRF
    let vrf = PDYPrivExtraVRF::<G1Affine>::new(&mut rng);

    // Generate secret key
    let sk = Fr::rand(&mut rng);

    // Pre-compute challenges for consistent testing
    let challenges: Vec<_> = (0..NUM_RUNS).map(|_| Fr::rand(&mut rng)).collect();

    // Precompute random inputs for eval_prove
    let eval_inputs: Vec<_> = (0..NUM_RUNS).map(|_| Fr::rand(&mut rng)).collect();
    let mut eval_idx = 0;

    // Benchmark eval_prove
    group.bench_function("eval_prove", |b| {
        b.iter(|| {
            let i = eval_idx % NUM_RUNS;
            eval_idx += 1;
            let x = eval_inputs[i];
            let witness = vrf.generate_full_witness(&sk, &x, &mut rng);
            let output = vrf.evaluate(&witness).expect("Failed to evaluate VRF");
            let _proof = vrf.prove_with_challenge(&witness, &output, &challenges[i], &mut rng);
        })
    });

    // Pre-compute witnesses, outputs, and proofs for verification
    let witnesses: Vec<_> = (0..NUM_RUNS)
        .map(|_| {
            let x = Fr::rand(&mut rng);
            vrf.generate_full_witness(&sk, &x, &mut rng)
        })
        .collect();

    let outputs: Vec<_> = witnesses
        .iter()
        .map(|witness| vrf.evaluate(witness).expect("Failed to evaluate VRF"))
        .collect();

    let proofs: Vec<_> = (0..NUM_RUNS)
        .map(|i| vrf.prove_with_challenge(&witnesses[i], &outputs[i], &challenges[i], &mut rng))
        .collect();

    let mut verify_idx = 0;
    // Benchmark verify
    group.bench_function("verify", |b| {
        b.iter(|| {
            let i = verify_idx % NUM_RUNS;
            verify_idx += 1;
            let is_valid = vrf.verify(&outputs[i].commitments, &proofs[i], &challenges[i]);
            assert!(is_valid, "P-DY-Priv-Extra-VRF verification failed");
        })
    });

    group.finish();
}

fn bench_dy_priv_vrf(c: &mut Criterion) {
    let mut group = c.benchmark_group("dy_priv");
    let mut rng = test_rng();

    // Initialize VRF
    let vrf = DYPrivVRF::<Bls12_381>::new(&mut rng);

    // Generate keys
    let (sk, pk) = vrf.generate_keys(&mut rng);

    // Precompute random inputs for eval_prove
    let eval_inputs: Vec<_> = (0..NUM_RUNS)
        .map(|_| DYPrivInput {
            ctx: <Bls12_381 as Pairing>::ScalarField::rand(&mut rng),
        })
        .collect();
    let mut eval_idx = 0;

    // Benchmark Eval + Prove
    group.bench_function("eval_prove", |b| {
        b.iter(|| {
            // Use a different input each time
            let input = &eval_inputs[eval_idx % NUM_RUNS];
            eval_idx += 1;
            let _output = vrf
                .evaluate(&sk, input, &mut rng)
                .expect("Failed to evaluate VRF");
        })
    });

    // Pre-compute some outputs for verification benchmarks
    let inputs: Vec<_> = (0..NUM_RUNS)
        .map(|_| DYPrivInput {
            ctx: <Bls12_381 as Pairing>::ScalarField::rand(&mut rng),
        })
        .collect();

    let evaluations: Vec<_> = inputs
        .iter()
        .map(|input| {
            vrf.evaluate(&sk, input, &mut rng)
                .expect("Failed to evaluate VRF")
        })
        .collect();

    let mut verify_idx = 0;
    // Benchmark verify
    group.bench_function("verify", |b| {
        b.iter(|| {
            let i = verify_idx % NUM_RUNS;
            verify_idx += 1;
            let (proof, _) = &evaluations[i];
            let is_valid = vrf.verify(&pk, &inputs[i], proof);
            assert!(is_valid, "DY-Priv VRF verification failed");
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_dy_vrf,
    bench_dy_priv_vrf,
    bench_dy_pf_vrf,
    bench_dy_pf_priv_vrf,
    bench_dy_pf_priv_committed_output_vrf
);
criterion_main!(benches);
