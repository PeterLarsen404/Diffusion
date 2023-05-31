import "diffusion"
import "../gen_random/mk_random"
import "../utils/optimizers"



def main (losses : []f64) (sampled_imgs : [][][]f64) (c_in_w : [][][][]f64) (c_in_b : []f64) (b1_c1_w : [][][][]f64) (b1_c1_b : []f64) (b1_tw : [][]f64) (b1_tb : []f64) (b1_c2_w : [][][][]f64) (b1_c2_b : []f64) (b2_c1_w : [][][][]f64) (b2_c1_b) (b2_tw : [][]f64) (b2_tb : []f64) (b2_c2_w : [][][][]f64) (b2_c2_b) (b3_c1_w : [][][][]f64) (b3_c1_b : []f64) (b3_tw : [][]f64) (b3_tb : []f64) (b3_c2_w : [][][][]f64) (b3_c2_b : []f64) (b4_c1_w : [][][][]f64) (b4_c1_b : []f64) (b4_tw : [][]f64) (b4_tb : []f64) (b4_c2_w : [][][][]f64) (b4_c2_b : []f64) (c_out_w : [][][][]f64) (c_out_b : []f64) =
  let trained_weights = ((c_in_w,c_in_b),(b1_c1_w,b1_c1_b,b1_tw,b1_tb,b1_c2_w,b1_c2_b),(b2_c1_w,b2_c1_b,b2_tw,b2_tb,b2_c2_w,b2_c2_b),(b3_c1_w,b3_c1_b,b3_tw,b3_tb,b3_c2_w,b3_c2_b),(b4_c1_w,b4_c1_b,b4_tw,b4_tb,b4_c2_w,b4_c2_b),(c_out_w,c_out_b))
  let beta = mk_beta 1000 0.0001 0.02
  let alpha = mk_alpha beta
  let alpha_bar = mk_alpha_bar alpha
  in sample  1 32 42 412 28 1000 beta alpha alpha_bar (trained_weights)

