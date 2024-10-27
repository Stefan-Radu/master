pub mod io;
#[cfg(test)]
mod test;

fn coord_to_index(row: u8, col: u8) -> usize {
    (col + 9 * row) as usize
}

fn is_permutation(values: &Vec<&Option<u8>>) -> bool {
    if values.len() != 9 {
        panic!("Only pass exactly 9 values to is_permutation");
    }

    for i in 0..values.len() {
        for j in 0..values.len() {
            if !values[i].is_none()  && i != j && values[i] == values[j] {
                return false;
            }
        }
    }
    true
}

fn is_permutation_row(grid: &Vec<Option<u8>>, row_index: u8) -> bool {
    let mut values = Vec::new();
    for col_index in 0..9 {
        values.push(&grid[coord_to_index(row_index, col_index)])
    }
    is_permutation(&values)
}

fn is_permutation_col(grid: &Vec<Option<u8>>, col_index: u8) -> bool {
    let mut values = Vec::new();
    for row_index in 0..9 {
        values.push(&grid[coord_to_index(row_index, col_index)])
    }
    is_permutation(&values)
}

fn is_permutation_block(grid: &Vec<Option<u8>>, block_row_index: u8, block_col_index: u8) -> bool {
    let mut values = Vec::new();
    for row_index in (block_row_index*3)..(block_row_index*3+3) {
        for col_index in (block_col_index*3)..(block_col_index*3+3) {
            values.push(&grid[coord_to_index(row_index, col_index)])
        }
    }
    is_permutation(&values)
}

fn is_valid(grid: &Vec<Option<u8>>) -> bool {
    for i in 0..9 {
        if !(is_permutation_col(grid, i) && is_permutation_row(grid, i)) {
            return false;
        }
    }
    for r in 0..3 {
        for c in 0..3 {
            if !is_permutation_block(grid, r, c) {
                return false;
            }
        }
    }
    true
}

pub fn solve(grid: &Vec<Option<u8>>) -> Option<Vec<Option<u8>>> {
    if grid.len() != 81 {
        panic!("grid passed to solve has to have exactly 81 values");
    }

    let mut mutable_grid = grid.to_owned();
    let mut counter = 0;
    while counter < 81 && grid[counter].is_some() {
        counter += 1;
    }
    if counter == 81 { // grid is fully solved
        return Some(mutable_grid);
    }
    let first_free_index = counter;
    for i in 1..10 {
        mutable_grid[first_free_index] = Some(i);
        if !is_valid(&mutable_grid) {
            continue;
        }
        let maybe_solution = solve(&mutable_grid);
        if maybe_solution.is_some() {
            return maybe_solution;
        }
    }

    None
}
