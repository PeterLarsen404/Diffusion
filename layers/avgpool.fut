def avg_pool [l][n][m] (imgs : [l][n][m]f64) (stride : i64) =
  let out_y = n/stride
  let out_x = m/stride
  let area_size = f64.i64 (stride*stride)
  in map (\img ->
    tabulate_2d out_y out_x (\ y x ->
      let area = img[(y*stride):(y*stride+stride), (x*stride):(x*stride+stride)]
      in reduce (+) 0 (flatten area) / area_size) :> [out_y][out_x]f64) imgs

def avg_pool_b [l][n][m] (imgs : [l][n][m]f64) (stride : i64) =
  let out_y = n*stride
  let out_x = m*stride
  let area_size = f64.i64 (stride*stride)
  in map (\img ->
    tabulate_2d out_y out_x (\ y x ->
      img[y/stride, x/stride] / area_size
    )
  ) imgs