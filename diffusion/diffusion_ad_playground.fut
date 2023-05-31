import "diffusion"
import "../gen_random/mk_random"
import "../utils/optimizers"

def main (x_train : [][][]f64)  =
let imgs = x_train[:1]
let epochs = 1

let seed = 82i32
let seeds = mk_rand_seeds seed 20

let time_seeds = tabulate 10 (\ x -> mk_rand_seeds ((i32.i64 x)+seeds[0]) 1)
let noise_seeds = tabulate 10 (\ x -> mk_rand_seeds ((i32.i64 x)+seeds[1])  1)

let beta = mk_beta 1000 0.0001 0.02
let alpha = mk_alpha beta
let alpha_bar = mk_alpha_bar alpha
let initial_weights = mk_unet_wandb seeds[2]
let initial_adam = mk_initial_adam ()
let num_groups = 32i64 -- Only tested for 32.

let trained_weights = train_unet_ad imgs alpha_bar num_groups epochs time_seeds noise_seeds initial_weights initial_adam

in trained_weights.0