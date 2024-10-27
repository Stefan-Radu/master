use crate::io::read_from_file;

#[test]
fn test_field1() {
    let field = read_from_file("input/field1.txt");
    let solution = read_from_file("input/field1_solution.txt");

    assert_eq!(Some(solution), crate::solve(&field));
}

#[test]
fn test_field2() {
    let field = read_from_file("input/field2.txt");
    let solution = read_from_file("input/field2_solution.txt");

    assert_eq!(Some(solution), crate::solve(&field));
}

#[test]
fn test_field3() {
    let field = read_from_file("input/field3.txt");
    let solution = read_from_file("input/field3_solution.txt");

    assert_eq!(Some(solution), crate::solve(&field));
}

#[test]
fn test_field4() {
    let field = read_from_file("input/field4.txt");
    let solution = read_from_file("input/field4_solution.txt");

    assert_eq!(Some(solution), crate::solve(&field));
}
