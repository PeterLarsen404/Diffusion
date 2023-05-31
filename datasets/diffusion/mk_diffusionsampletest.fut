import "../../gen_random/mk_random"
import "../../diffusion/diffusion"

def main (seed : i32) =
  let num_imgs = 2i64
  let beta = mk_beta 1000 0.0001 0.02
  let alpha = mk_alpha beta
  let alpha_bar = mk_alpha_bar alpha
  let seeds = mk_rand_seeds seed 2
  in (num_imgs,beta,alpha,alpha_bar,seeds[0],seeds[1])



