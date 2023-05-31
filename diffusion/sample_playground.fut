import "diffusion"
import "../gen_random/mk_random"
import "../utils/optimizers"
def main (num_imgs : i64) (beta : []f64) (alpha : []f64) (alpha_bar : []f64) (x_seed : i32) (eps_seed : i32) (denoise_steps : i64) =
  let seed = 82i32
  let initial_weights = mk_unet_wandb seed
  let sampled_imgs = sample num_imgs 32 x_seed eps_seed 28 denoise_steps beta alpha alpha_bar initial_weights
  in sampled_imgs

