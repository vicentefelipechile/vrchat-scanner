use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_entropy(c: &mut Criterion) {
    let data: Vec<u8> = (0u8..=255u8).cycle().take(1_000_000).collect();
    c.bench_function("shannon_entropy_1MB", |b| {
        b.iter(|| vrcstorage_scanner::utils::shannon_entropy(black_box(&data)));
    });
}

fn bench_script_analysis(c: &mut Criterion) {
    let source = include_str!("../tests/fixtures/clean/clean_script.cs").as_bytes();
    c.bench_function("analyze_script_clean", |b| {
        b.iter(|| {
            vrcstorage_scanner::analysis::scripts::analyze_script(
                black_box(source),
                "cli",
                "Assets/Scripts/Clean.cs",
            )
        });
    });
}

criterion_group!(benches, bench_entropy, bench_script_analysis);
criterion_main!(benches);
