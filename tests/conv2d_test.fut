import "../layers/conv2d"
import "../utils/linalg"

-- conv2d test, in_ch = 1, out_ch = 2, img_shape = 4x4, kernel_size = 3x3, padding = 1
-- ==
-- entry: convolve2d_test
-- compiled input @ ../datasets/conv2d/test_1_2_4_3.in
-- output @ ../datasets/conv2d/test_1_2_4_3.out

-- conv2d test, in_ch = 2, out_ch = 1, img_shape = 10x10, kernel_size = 7x7, padding = 2
-- ==
-- entry: convolve2d_test
-- compiled input @ ../datasets/conv2d/test_2_1_10_7.in
-- output @ ../datasets/conv2d/test_2_1_10_7.out

--
-- ==
-- entry: convolve2d_b_test
-- compiled input @ ../datasets/conv2d/test_1_2_4_3_b.in
-- output @ ../datasets/conv2d/test_1_2_4_3_b.out

--
-- ==
-- entry: convolve2d_b_test
-- compiled input @ ../datasets/conv2d/test_2_1_10_7_b.in
-- output @ ../datasets/conv2d/test_2_1_10_7_b.out


-- Bench conv2d
-- U-Net use cases
-- Importance of spatial input size and kernel size
-- Importance of input and output channels
-- ==
-- entry: convolve2d_test
-- compiled random input {[1][28][28]f64 [64][1][3][3]f64 [64]f64 1i64}
-- compiled random input {[512][28][28]f64 [128][512][3][3]f64 [128]f64 1i64}
-- compiled random input {[1024][28][28]f64 [256][1024][3][3]f64 [256]f64 1i64}
-- compiled random input {[1][64][64]f64 [1][1][3][3]f64 [1]f64 1i64}
-- compiled random input {[1][64][64]f64 [1][1][7][7]f64 [1]f64 1i64}
-- compiled random input {[1][512][512]f64 [1][1][3][3]f64 [1]f64 1i64}
-- compiled random input {[1][1024][1024]f64 [1][1][3][3]f64 [1]f64 1i64}
-- compiled random input {[1][1][1]f64 [1024][1][3][3]f64 [1024]f64 1i64}
-- compiled random input {[1024][1][1]f64 [1][1024][3][3]f64 [1]f64 1i64}

-- Bench conv2d_b
-- U-Net use cases
-- Importance of spatial input size and kernel size
-- Importance of input and output channels
-- ==
-- entry: convolve2d_b_test
-- compiled random input {[64][28][28]f64 [1][28][28]f64 [64][1][3][3]f64 1i64 1i64}
-- compiled random input {[128][28][28]f64 [512][28][28]f64 [128][512][3][3]f64 1i64 1i64}
-- compiled random input {[256][28][28]f64 [1024][28][28]f64 [256][1024][3][3]f64 1i64 1i64}
-- compiled random input {[1][64][64]f64 [1][64][64]f64 [1][1][3][3]f64 1i64 1i64}
-- compiled random input {[1][60][60]f64 [1][64][64]f64 [1][1][7][7]f64 1i64 5i64}
-- compiled random input {[1][512][512]f64 [1][512][512]f64 [1][1][3][3]f64 1i64 1i64}
-- compiled random input {[1][1024][1024]f64 [1][1024][1024]f64 [1][1][3][3]f64 1i64 1i64}
-- compiled random input {[1024][1][1]f64 [1][1][1]f64 [1024][1][3][3]f64 1i64 1i64}
-- compiled random input {[1][1][1]f64 [1024][1][1]f64 [1][1024][3][3]f64 1i64 1i64}


entry convolve2d_test [n][m][p][k][l][o] (imgs : [l][n][m]f64) (kernels : [o][l][p][k]f64) (biases : [o]f64) (padding : i64) =
  convolve2D imgs kernels biases padding

entry convolve2d_b_test [n][m][p][k][l][o][q][r] (out_grad : [o][q][r]f64) (conv_input : [l][n][m]f64) (kernels : [o][l][p][k]f64) (valid_num : i64) (full_num : i64)=
  convolve2D_b out_grad conv_input kernels valid_num full_num

entry convolve2d_b_bench [n][m][p][k][l][o][q][r] (out_grad : [o][q][r]f64) (conv_input : [l][n][m]f64) (kernels : [o][l][p][k]f64) =
  convolve2D_b out_grad conv_input kernels 0 1
