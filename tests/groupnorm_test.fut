import "../layers/groupnorm"


-- test groupnorm forward
-- ==
-- entry: groupnorm_test
-- compiled input @ ../datasets/groupnorm/test_4_2.in
-- output @ ../datasets/groupnorm/test_4_2.out

-- test groupnorm backward
-- ==
-- entry: groupnorm_test_b
-- compiled input @ ../datasets/groupnorm/test_4_2_b.in
-- output @ ../datasets/groupnorm/test_4_2_b.out


-- bench forward groupnorm
-- ==
-- entry: groupnorm_test
-- compiled random input {[64][28][28]f64 32i64}
-- compiled random input {[256][28][28]f64 32i64}
-- compiled random input {[512][56][56]f64 32i64}

-- bench backwards groupnorm
-- ==
-- entry: groupnorm_bench_b
-- compiled input @ ../datasets/groupnorm/test_64_28_b.in
-- compiled input @ ../datasets/groupnorm/test_256_28_b.in
-- compiled input @ ../datasets/groupnorm/test_512_56_b.in

entry groupnorm_test [l][m][n] (img : [l][m][n]f64) (num_groups : i64)=
  let (out, (out_, var, elem_groups)) = (group_norm img num_groups 1e-5)
  in(out,var,elem_groups)

entry groupnorm_test_b [l][m][n] (img : [l][m][n]f64) (num_groups : i64) (cache0 : [l][m][n]f64) (cache1 : []f64) (cache2 : i64)  =
  group_norm_b img num_groups 1e-5 (cache0,cache1,cache2)

entry groupnorm_bench_b [l][m][n] (img : [l][m][n]f64) (cache0 : [l][m][n]f64) (cache1 : []f64) (cache2 : i64)  =
  group_norm_b img 32 1e-5 (cache0,cache1,cache2)

