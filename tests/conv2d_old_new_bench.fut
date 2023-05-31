import "../layers/conv2d"

def naive_convolve2D [n][m][p][k][l][o] (imgs : [l][n][m]f64) (kernels : [o][l][p][k]f64) (biases : [o]f64) (padding : i64) =
  let flat_pk = p*k
  let new_n = (((n+(padding*2))-p)+1)
  let new_m = (((m+(padding*2))-p)+1)

  let imgs_padded =
    if (padding != 0) then
      add_padding imgs padding
    else
      imgs

  let c1 = map (\ kernel_3d ->
    tabulate_2d new_n new_m (\ y x ->
      reduce (+) 0 (flatten (map2 (\ kernel img ->
        (flatten (map2 (\ i j ->
          map2 (*) i j)
        (img[y:(y+p),x:(x+k)] :> [p][k]f64) kernel)) :> [flat_pk]f64
      ) kernel_3d imgs_padded))
    )
  ) kernels

  let c1_b = tabulate_3d o new_n new_m (\z y x -> c1[z,y,x] + biases[z])
  in c1_b

-- ==
-- entry: naive_convolve2d_test
-- compiled random input {[50][50][50]f64 [100][50][3][3]f64 [100]f64 1i64}
-- compiled random input {[200][50][50]f64 [400][200][3][3]f64 [400]f64 1i64}
-- compiled random input {[500][100][100]f64 [1000][500][3][3]f64 [1000]f64 1i64}

-- ==
-- entry: convolve2d_test
-- compiled random input {[50][50][50]f64 [100][50][3][3]f64 [100]f64 1i64}
-- compiled random input {[200][50][50]f64 [400][200][3][3]f64 [400]f64 1i64}
-- compiled random input {[500][100][100]f64 [1000][500][3][3]f64 [1000]f64 1i64}

entry naive_convolve2d_test [n][m][p][k][l][o] (imgs : [l][n][m]f64) (kernels : [o][l][p][k]f64) (biases : [o]f64) (padding : i64) =
  naive_convolve2D imgs kernels biases padding

entry convolve2d_test [n][m][p][k][l][o] (imgs : [l][n][m]f64) (kernels : [o][l][p][k]f64) (biases : [o]f64) (padding : i64) =
  convolve2D imgs kernels biases padding