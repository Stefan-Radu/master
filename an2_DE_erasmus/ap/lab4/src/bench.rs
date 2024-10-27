use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sudoku::io::read_from_file;

fn criterion_benchmark(c: &mut Criterion) {
    let field1 = read_from_file("input/field1.txt");
    let field2 = read_from_file("input/field2.txt");
    let field3 = read_from_file("input/field3.txt");
    let field4 = read_from_file("input/field4.txt");
    c.bench_function("field1", |b| b.iter(|| sudoku::solve(black_box(&field1))));
    c.bench_function("field2", |b| b.iter(|| sudoku::solve(black_box(&field2))));
    c.bench_function("field3", |b| b.iter(|| sudoku::solve(black_box(&field3))));
    c.bench_function("field4", |b| b.iter(|| sudoku::solve(black_box(&field4))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
