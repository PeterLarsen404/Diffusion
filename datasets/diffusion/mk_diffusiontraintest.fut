import "../../gen_random/mk_random"
import "../../diffusion/diffusion"

def main (dataset : [][][]f64) =
  let total_img = dataset[:1]
  let epochs = 3i64
  let seeds = mk_rand_seeds 3141 2
  let time_seeds = tabulate epochs (\ x -> mk_rand_seeds ((i32.i64 x)+seeds[0]) 1)
  let noise_seeds = tabulate epochs (\ x -> mk_rand_seeds ((i32.i64 x)+seeds[1]) 1)

  let beta = mk_beta 1000 0.0001 0.02
  let alpha = mk_alpha beta
  let alpha_bar = mk_alpha_bar alpha
  in (total_img,alpha_bar,epochs,time_seeds,noise_seeds)