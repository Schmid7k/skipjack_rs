use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use criterion_cycles_per_byte::CyclesPerByte;
use skipjack_rs::*;

fn bench(c: &mut Criterion<CyclesPerByte>) {
    let mut group = c.benchmark_group("skipjack_encrypt");

    let cipher = Skipjack::new([0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42].into());

    let mut buf = [42; 4].into();

    group.throughput(Throughput::Bytes(8 as u64));

    group.bench_function(BenchmarkId::new("encrypt-64", 8), |b| {
        b.iter(|| cipher.encrypt(&mut buf));
    });

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = bench
);

criterion_main!(benches);
