import "../utils/linalg"

def add_padding [l][n][m] (imgs : [l][n][m]f64) (padding : i64) =
  let n_pad = (n+(padding*2))
  let m_pad = (m+(padding*2))
  in map (\ img_i -> tabulate_2d n_pad m_pad (\ i j ->
      if (i < padding || i >= (n+padding) || j < padding || j >= (m+padding)) then 0 else img_i[i-padding,j-padding])) imgs

def im2col [l][n][m] (img : [l][n][m]f64) (total : i64) (kernel_size : i64) (new_n : i64) (new_m : i64) =
  let k_total = kernel_size*kernel_size
  in transpose (flatten (tabulate_2d new_n new_m (\ y x -> flatten (map (\ i -> flatten (i[y:y+kernel_size, x:x+kernel_size]) :> [k_total]f64) img) :> [total]f64)))

def convolve2D [n][m][p][k][l][o] (imgs : [l][n][m]f64) (kernels : [o][l][p][k]f64) (biases : [o]f64) (padding : i64) =
  let new_n = (((n+(padding*2))-p)+1)
  let new_m = (((m+(padding*2))-p)+1)
  let total = l*p*k

  let imgs_padded =
    if (padding != 0) then
      add_padding imgs padding
    else
      imgs

  let img_col = im2col imgs_padded total p new_n new_m
  let kernel_col = map (\ x -> flatten_3d x :> [total]f64) kernels
  let res = matmul kernel_col img_col
  let res_bias = map2 (\ r b -> map (+b) r) res biases
  in map (unflatten new_n new_m) res_bias


def convolve2D_b [n][m][p][k][l][o][q][r] (out_grad : [o][q][r]f64) (conv_input : [l][n][m]f64) (kernels : [o][l][p][k]f64) (valid_num : i64) (full_num : i64) : ([l][n][m]f64, [o][l][p][k]f64,[o]f64)  =
  let kernels_grad = tabulate_2d o l (\ i j -> flatten (convolve2D [conv_input[j]] [[out_grad[i]]] [0f64] valid_num) :> [p][k]f64)
  let input_grad = convolve2D out_grad (transpose kernels[:,:,::-1,::-1]) (replicate l 0f64) full_num :> [l][n][m]f64
  let biases_grad = map (\ x -> reduce (+) 0 (flatten x)) out_grad
  in (input_grad, kernels_grad, biases_grad)
