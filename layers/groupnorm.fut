def group_arr [l][m][n] (img : [l][m][n]f64) (num_groups : i64) (elem_groups : i64) : [num_groups][elem_groups][m][n]f64 =
  tabulate num_groups (\ x -> img[(x*elem_groups):((x+1)*elem_groups)] :> [elem_groups][m][n]f64)

def mean [n] (img : [n]f64) : f64 =
  f64.sum img / f64.i64 n

def variance [n] (vs: [n]f64) =
  let m = mean vs
  let xs = map (\x -> (x-m)*(x-m)) vs
  in f64.sum xs / (f64.i64 n)

def mean_and_var [l][n][m] (img : [l][n][m]f64) : (f64,f64) =
  let flat_img = flatten_3d img
  let img_mean = mean flat_img
  let img_var = variance flat_img
  in (img_mean, img_var)

def group_norm [l][m][n] (img : [l][m][n]f64) (num_groups : i64) (eps : f64)  =
  let elem_groups = l / num_groups
  let group_img = group_arr img num_groups elem_groups
  let (mean_grouped,var_grouped) = unzip (map mean_and_var group_img)
  let out = tabulate_3d l m n (\ z y x -> (img[z,y,x] - mean_grouped[z / elem_groups]) / f64.sqrt (var_grouped[z / elem_groups] + eps))
  in (out,(out,var_grouped,elem_groups))


def group_norm_b [l][m][n] (out_grad : [l][m][n]f64) (num_groups : i64) (eps : f64) (cache) : [l][m][n]f64 =
  let (out, var, elem_groups) = cache
  let elem_in_group = elem_groups * m * n
  let group_out = group_arr out num_groups elem_groups
  let group_grad = group_arr out_grad num_groups elem_groups
  let elem_in_group_f64 = f64.i64 elem_in_group

  let grad_sum_and_mult_sum =
    map2 (\x y ->
      let flat_x = flatten_3d x :> [elem_in_group]f64
      let flat_y = flatten_3d y :> [elem_in_group]f64
      in (reduce (+) 0 flat_x, reduce (+) 0 (map2 (*) flat_x flat_y)))
    group_grad group_out

  let res =
    tabulate num_groups (\d ->
      let (grad_sum, grad_out_mult_sum) = grad_sum_and_mult_sum[d]
      in tabulate_3d elem_groups m n (\ z y x ->
        (1f64 / elem_in_group_f64) *
        (elem_in_group_f64 * group_grad[d,z,y,x] - grad_sum - group_out[d,z,y,x] * grad_out_mult_sum) /
        f64.sqrt(var[d] + eps)))

  in flatten res :> [l][m][n]f64

