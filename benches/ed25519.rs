use nullifiers::{
    dy_pf::{DYPFVRFInput, DYPFVRF},
    dy_pf_priv::{DYPFPrivPublicKey, DYPFPrivVRF, DYPFPrivVRFWitness},
    dy_pf_priv_commited_output::PDYPrivExtraVRF,
};

use ark_ed25519::{EdwardsAffine as Ed25519Affine, Fr};
use ark_ff::UniformRand;
use ark_std::test_rng;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

// Number of runs for each benchmark
const NUM_RUNS: usize = 100;

fn bench_dy_pf_vrf_ed25519(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519_dy_pf");
    let mut rng = test_rng();

    // Initialize VRF with Ed25519
    let vrf = DYPFVRF::<Ed25519Affine>::new(&mut rng);

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

fn bench_dy_pf_priv_vrf_ed25519(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519_dy_pf_priv");
    let mut rng = test_rng();

    // Initialize VRF with Ed25519
    let vrf = DYPFPrivVRF::<Ed25519Affine>::new(&mut rng);

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
    let witnesses_and_commitments: Vec<(DYPFPrivVRFWitness<Fr>, Ed25519Affine)> = (0..NUM_RUNS)
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
    let pks: Vec<DYPFPrivPublicKey<Ed25519Affine>> = witnesses_and_commitments
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
    group.bench_function("verify", |b| {
        b.iter(|| {
            let i = verify_idx % NUM_RUNS;
            verify_idx += 1;
            let is_valid = vrf.verify(&pks[i], &outputs[i], &proofs[i], &challenges[i]);
            assert!(is_valid, "P-DY-Priv-VRF verification failed");
        })
    });

    group.finish();
}

fn bench_dy_pf_priv_committed_output_vrf_ed25519(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519_dy_pf_priv_committed_output");
    let mut rng = test_rng();

    // Initialize VRF with Ed25519
    let vrf = PDYPrivExtraVRF::<Ed25519Affine>::new(&mut rng);

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

criterion_group!(
    ed25519_benches,
    bench_dy_pf_vrf_ed25519,
    bench_dy_pf_priv_vrf_ed25519,
    bench_dy_pf_priv_committed_output_vrf_ed25519
);
criterion_main!(ed25519_benches);
